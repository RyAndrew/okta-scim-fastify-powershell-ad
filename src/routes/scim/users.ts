// ---------------------------------------------------------------------------
// SCIM 2.0 /Users endpoint
//
// Implements RFC 7644 §3.3 – §3.6 for User resources:
//   GET    /scim/v2/Users          — list / search
//   GET    /scim/v2/Users/:id      — read single user
//   POST   /scim/v2/Users          — create user
//   PUT    /scim/v2/Users/:id      — full replace
//   PATCH  /scim/v2/Users/:id      — partial update
//   DELETE /scim/v2/Users/:id      — deprovision
//
// Every mutating request:
//   1. Updates the scim_users local cache (optimistic write)
//   2. Executes the relevant AD cmdlet via PowerShell
//   3. Re-reads the user with Get-ADUser to refresh ad_resource
//   4. Updates sync_status + last_error based on the PS outcome
// ---------------------------------------------------------------------------

import { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { v4 as uuidv4 } from 'uuid';
import { db } from '../../db';
import { config } from '../../config';
import { scimToAdParams } from '../../config/mapping';
import {
  formatScimUser,
  formatListResponse,
  formatError,
  mapPsErrorToScim,
} from '../../scim/formatter';
import { parseScimFilter } from '../../scim/filter-parser';
import { applyPatchOps } from '../../scim/patch-applier';
import {
  execNewAdUser,
  execSetAdUser,
  execRemoveAdUser,
  execGetAdUser,
  extractObjectGuid,
} from '../../powershell';
import {
  ScimUser,
  ScimPatchOp,
  ScimUserRow,
} from '../../scim/types';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function baseUrl(request: FastifyRequest): string {
  return `${request.protocol}://${request.hostname}`;
}

function now(): string {
  return new Date().toISOString();
}

/**
 * After any AD mutation, refresh the user from AD and update ad_resource
 * in the local DB.  Errors are swallowed — the SCIM operation has already
 * succeeded and we don't want a read-back failure to roll it back.
 */
async function refreshAdResource(
  identity: string,
  scimUserId: string,
  server: FastifyInstance,
): Promise<void> {
  try {
    const adUser = await execGetAdUser(identity, scimUserId);
    if (adUser) {
      await db('scim_users').where({ id: scimUserId }).update({
        ad_resource: JSON.stringify(adUser),
        updated_at: now(),
      });
    }
  } catch (err) {
    server.log.warn({ err, scimUserId }, 'Failed to refresh ad_resource after sync');
  }
}

// ---------------------------------------------------------------------------
// Route plugin
// ---------------------------------------------------------------------------

export async function scimUsersRoutes(server: FastifyInstance): Promise<void> {
  // All SCIM endpoints require HTTP Basic auth (password = API_KEY)
  server.addHook('onRequest', server.authenticate);

  // ──────────────────────────────────────────────────────────────────────────
  // GET /scim/v2/Users
  // ──────────────────────────────────────────────────────────────────────────

  server.get<{
    Querystring: {
      filter?: string;
      startIndex?: string;
      count?: string;
    };
  }>('/', async (request, reply: FastifyReply) => {
    const { filter, startIndex: startIndexStr, count: countStr } = request.query;
    const startIndex = Math.max(1, parseInt(startIndexStr ?? '1', 10));
    const pageSize = Math.min(200, Math.max(1, parseInt(countStr ?? '100', 10)));

    try {
      let query = db<ScimUserRow>('scim_users');
      let countQuery = db<ScimUserRow>('scim_users');

      if (filter) {
        const parsed = parseScimFilter(filter);
        if (parsed) {
          // Known column — apply SQL predicate
          if (parsed.operator === 'eq') {
            query = query.where(parsed.dbColumn, parsed.value);
            countQuery = countQuery.where(parsed.dbColumn, parsed.value);
          }
          // Other operators (ne, co, sw…) could be added here as needed
        }
        // Unrecognised filter attributes: fall through and return all rows;
        // a production implementation would do a full-text JSON scan or a PS query.
      }

      const [{ total }] = await countQuery.count<[{ total: number }]>('id as total');
      const rows = await query
        .orderBy('created_at', 'asc')
        .offset(startIndex - 1)
        .limit(pageSize)
        .select();

      const users = rows.map((row) => formatScimUser(row, baseUrl(request)));

      return reply
        .status(200)
        .header('Content-Type', 'application/scim+json')
        .send(formatListResponse(users, Number(total), startIndex));
    } catch (err) {
      server.log.error({ err }, 'GET /Users failed');
      return reply
        .status(500)
        .send(formatError(500, 'Internal server error'));
    }
  });

  // ──────────────────────────────────────────────────────────────────────────
  // GET /scim/v2/Users/:id
  // ──────────────────────────────────────────────────────────────────────────

  server.get<{ Params: { id: string } }>(
    '/:id',
    async (request, reply: FastifyReply) => {
      const { id } = request.params;

      try {
        const row = await db<ScimUserRow>('scim_users').where({ id }).first();
        if (!row) {
          return reply
            .status(404)
            .send(formatError(404, `User ${id} not found.`, 'noTarget'));
        }

        return reply
          .status(200)
          .header('Content-Type', 'application/scim+json')
          .send(formatScimUser(row, baseUrl(request)));
      } catch (err) {
        server.log.error({ err, id }, 'GET /Users/:id failed');
        return reply.status(500).send(formatError(500, 'Internal server error'));
      }
    },
  );

  // ──────────────────────────────────────────────────────────────────────────
  // POST /scim/v2/Users  — provision a new user
  // ──────────────────────────────────────────────────────────────────────────

  server.post<{ Body: ScimUser }>('/', async (request, reply: FastifyReply) => {
    const scimUser = request.body;

    if (!scimUser.userName) {
      return reply
        .status(400)
        .send(formatError(400, 'userName is required.', 'invalidValue'));
    }

    // Idempotency: reject if a user with the same userName already exists
    const duplicate = await db<ScimUserRow>('scim_users')
      .where({ sam_account_name: scimUser.userName.split('@')[0].substring(0, 20) })
      .first();

    if (duplicate) {
      return reply
        .status(409)
        .send(
          formatError(
            409,
            `A user with userName '${scimUser.userName}' already exists.`,
            'uniqueness',
          ),
        );
    }

    // Use externalId (Okta user ID) as our SCIM id for easy correlation
    const userId = scimUser.externalId ?? uuidv4();
    const scimResource = { ...scimUser, id: userId };

    // ── Execute New-ADUser ────────────────────────────────────────────────
    const adParams = scimToAdParams(
      scimUser as unknown as Record<string, unknown>,
      config.ad.baseOu,
    );

    const psResult = await execNewAdUser(
      { ...adParams, AccountPassword: config.ad.defaultPassword },
      userId,
    );

    if (psResult.exitCode !== 0) {
      const { status, scimType, detail } = mapPsErrorToScim(psResult.stderr);
      return reply.status(status).send(formatError(status, detail, scimType));
    }

    // ── Persist objectGUID ────────────────────────────────────────────────
    const objectGuid = extractObjectGuid(psResult.parsed);
    const ts = now();

    await db('scim_users').insert({
      id: userId,
      sam_account_name: scimUser.userName.split('@')[0].substring(0, 20),
      scim_resource: JSON.stringify(scimResource),
      ad_object_guid: objectGuid ?? null,
      sync_status: 'synced',
      created_at: ts,
      updated_at: ts,
    });

    // ── Refresh ad_resource from AD ───────────────────────────────────────
    if (objectGuid) {
      await refreshAdResource(objectGuid, userId, server);
    }

    const row = await db<ScimUserRow>('scim_users').where({ id: userId }).first();

    return reply
      .status(201)
      .header('Location', `${baseUrl(request)}/scim/v2/Users/${userId}`)
      .header('Content-Type', 'application/scim+json')
      .send(formatScimUser(row!, baseUrl(request)));
  });

  // ──────────────────────────────────────────────────────────────────────────
  // PUT /scim/v2/Users/:id  — full replace
  // ──────────────────────────────────────────────────────────────────────────

  server.put<{ Params: { id: string }; Body: ScimUser }>(
    '/:id',
    async (request, reply: FastifyReply) => {
      const { id } = request.params;
      const scimUser = request.body;

      const row = await db<ScimUserRow>('scim_users').where({ id }).first();
      if (!row) {
        return reply
          .status(404)
          .send(formatError(404, `User ${id} not found.`, 'noTarget'));
      }

      // Persist the new SCIM state
      const scimResource = { ...scimUser, id };
      await db('scim_users').where({ id }).update({
        scim_resource: JSON.stringify(scimResource),
        sam_account_name: scimUser.userName ? scimUser.userName.split('@')[0].substring(0, 20) : row.sam_account_name,
        sync_status: 'pending',
        updated_at: now(),
      });

      // ── Execute Set-ADUser ──────────────────────────────────────────────
      const identity = row.ad_object_guid ?? row.sam_account_name;
      if (!identity) {
        return reply
          .status(500)
          .send(formatError(500, 'Cannot identify AD account: no objectGUID or samAccountName.'));
      }

      const adParams = scimToAdParams(scimUser as unknown as Record<string, unknown>);
      const { Name: _n, Path: _p, ...setParams } = adParams;

      const psResult = await execSetAdUser(identity, setParams, id);

      if (psResult.exitCode !== 0) {
        const { status, scimType, detail } = mapPsErrorToScim(psResult.stderr);
        await db('scim_users').where({ id }).update({
          sync_status: 'error',
          last_error: psResult.stderr.substring(0, 2000),
          updated_at: now(),
        });
        return reply.status(status).send(formatError(status, detail, scimType));
      }

      await db('scim_users').where({ id }).update({
        sync_status: 'synced',
        last_error: null,
        updated_at: now(),
      });

      await refreshAdResource(identity, id, server);

      const updated = await db<ScimUserRow>('scim_users').where({ id }).first();
      return reply
        .status(200)
        .header('Content-Type', 'application/scim+json')
        .send(formatScimUser(updated!, baseUrl(request)));
    },
  );

  // ──────────────────────────────────────────────────────────────────────────
  // PATCH /scim/v2/Users/:id  — partial update (RFC 7644 §3.5.2)
  // ──────────────────────────────────────────────────────────────────────────

  server.patch<{ Params: { id: string }; Body: ScimPatchOp }>(
    '/:id',
    async (request, reply: FastifyReply) => {
      const { id } = request.params;
      const patchBody = request.body;

      if (
        !Array.isArray(patchBody.Operations) ||
        patchBody.Operations.length === 0
      ) {
        return reply
          .status(400)
          .send(formatError(400, 'Operations array is required and must not be empty.', 'invalidValue'));
      }

      const row = await db<ScimUserRow>('scim_users').where({ id }).first();
      if (!row) {
        return reply
          .status(404)
          .send(formatError(404, `User ${id} not found.`, 'noTarget'));
      }

      // Apply patch ops to the cached SCIM resource
      const currentResource = JSON.parse(row.scim_resource) as Record<string, unknown>;
      const { updated: patchedResource, changedFields } = applyPatchOps(
        currentResource,
        patchBody.Operations,
      );

      // Persist the patched SCIM resource
      await db('scim_users').where({ id }).update({
        scim_resource: JSON.stringify({ ...patchedResource, id }),
        sync_status: 'pending',
        updated_at: now(),
      });

      // ── Execute Set-ADUser with only the changed attributes ─────────────
      const identity = row.ad_object_guid ?? row.sam_account_name;
      if (!identity) {
        return reply
          .status(500)
          .send(formatError(500, 'Cannot identify AD account: no objectGUID or samAccountName.'));
      }

      const adParams = scimToAdParams(changedFields);
      // Remove Name / Path — not valid Set-ADUser params
      const { Name: _n, Path: _p, ...setParams } = adParams;

      // Only call Set-ADUser if there is something to change
      if (Object.keys(setParams).length > 0) {
        const psResult = await execSetAdUser(identity, setParams, id);

        if (psResult.exitCode !== 0) {
          const { status, scimType, detail } = mapPsErrorToScim(psResult.stderr);
          await db('scim_users').where({ id }).update({
            sync_status: 'error',
            last_error: psResult.stderr.substring(0, 2000),
            updated_at: now(),
          });
          return reply.status(status).send(formatError(status, detail, scimType));
        }
      }

      await db('scim_users').where({ id }).update({
        sync_status: 'synced',
        last_error: null,
        updated_at: now(),
      });

      await refreshAdResource(identity, id, server);

      const updated = await db<ScimUserRow>('scim_users').where({ id }).first();
      return reply
        .status(200)
        .header('Content-Type', 'application/scim+json')
        .send(formatScimUser(updated!, baseUrl(request)));
    },
  );

  // ──────────────────────────────────────────────────────────────────────────
  // DELETE /scim/v2/Users/:id  — deprovision
  // ──────────────────────────────────────────────────────────────────────────

  server.delete<{ Params: { id: string } }>(
    '/:id',
    async (request, reply: FastifyReply) => {
      const { id } = request.params;

      const row = await db<ScimUserRow>('scim_users').where({ id }).first();
      if (!row) {
        return reply
          .status(404)
          .send(formatError(404, `User ${id} not found.`, 'noTarget'));
      }

      const identity = row.ad_object_guid ?? row.sam_account_name;

      if (identity) {
        const psResult = await execRemoveAdUser(identity, id);

        if (psResult.exitCode !== 0) {
          // If the user is already gone in AD, treat it as success
          const alreadyGone =
            psResult.stderr.toLowerCase().includes('cannot find') ||
            psResult.stderr.toLowerCase().includes('not found');

          if (!alreadyGone) {
            const { status, scimType, detail } = mapPsErrorToScim(psResult.stderr);
            return reply.status(status).send(formatError(status, detail, scimType));
          }
        }
      }

      await db('scim_users').where({ id }).delete();

      return reply.status(204).send();
    },
  );
}
