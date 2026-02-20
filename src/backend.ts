// ---------------------------------------------------------------------------
// Active Directory backend implementation
//
// Implements ScimBackend using PowerShell cmdlets for all AD operations.
// User state is cached in a local SQLite database; every AD operation is
// audited in the powershell_executions table.
// ---------------------------------------------------------------------------

import { randomUUID } from 'crypto';
import {
  ScimBackend,
  ScimBackendError,
  ScimUser,
  ScimPatchOp,
  ListUsersOptions,
  ListUsersResult,
  SCIM_SCHEMA_USER,
  applyPatchOps,
} from 'scim-fastify-core';
import type { Knex } from 'knex';
import {
  execNewAdUser,
  execSetAdUser,
  execRemoveAdUser,
  execGetAdUser,
  extractObjectGuid,
} from './powershell';
import { scimToAdParams } from './config/mapping';
import { mapPsErrorToScim } from './ps-errors';
import type { ScimUserRow } from './types';

// ---------------------------------------------------------------------------
// Attribute → SQLite column map for filter translation
// ---------------------------------------------------------------------------

const FILTER_ATTR_TO_COLUMN: Record<string, string> = {
  id: 'id',
  externalid: 'id',
  username: 'sam_account_name',
};

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

export class PowerShellAdBackend implements ScimBackend {
  constructor(
    private readonly db: Knex,
    private readonly config: {
      ad: { baseOu: string; defaultPassword: string };
    },
  ) {}

  // ── List ────────────────────────────────────────────────────────────────

  async listUsers({ filter, startIndex, count }: ListUsersOptions): Promise<ListUsersResult> {
    let query = this.db<ScimUserRow>('scim_users');
    let countQuery = this.db<ScimUserRow>('scim_users');

    if (filter && filter.operator === 'eq') {
      const col = FILTER_ATTR_TO_COLUMN[filter.attribute.toLowerCase()];
      if (col) {
        query = query.where(col, filter.value);
        countQuery = countQuery.where(col, filter.value);
      }
    }

    const [{ total }] = await countQuery.count<[{ total: number }]>('id as total');
    const rows = await query
      .orderBy('created_at', 'asc')
      .offset(startIndex - 1)
      .limit(count)
      .select();

    return {
      users: rows.map((r) => this.rowToScimUser(r)),
      totalResults: Number(total),
    };
  }

  // ── Get ─────────────────────────────────────────────────────────────────

  async getUser(id: string): Promise<ScimUser> {
    const row = await this.db<ScimUserRow>('scim_users').where({ id }).first();
    if (!row) {
      throw new ScimBackendError(404, `User ${id} not found.`, 'noTarget');
    }
    return this.rowToScimUser(row);
  }

  // ── Create ───────────────────────────────────────────────────────────────

  async createUser(user: ScimUser): Promise<ScimUser> {
    const samAccountName = user.userName.split('@')[0].substring(0, 20);

    const duplicate = await this.db<ScimUserRow>('scim_users')
      .where({ sam_account_name: samAccountName })
      .first();

    if (duplicate) {
      throw new ScimBackendError(
        409,
        `A user with userName '${user.userName}' already exists.`,
        'uniqueness',
      );
    }

    const userId = user.externalId ?? randomUUID();
    const scimResource = { ...user, id: userId };

    const adParams = scimToAdParams(
      user as unknown as Record<string, unknown>,
      this.config.ad.baseOu,
    );

    const psResult = await execNewAdUser(
      { ...adParams, AccountPassword: this.config.ad.defaultPassword },
      userId,
    );

    if (psResult.exitCode !== 0) {
      const { status, scimType, detail } = mapPsErrorToScim(psResult.stderr);
      throw new ScimBackendError(status, detail, scimType);
    }

    const objectGuid = extractObjectGuid(psResult.parsed);
    const ts = now();

    await this.db('scim_users').insert({
      id: userId,
      sam_account_name: samAccountName,
      scim_resource: JSON.stringify(scimResource),
      ad_object_guid: objectGuid ?? null,
      sync_status: 'synced',
      created_at: ts,
      updated_at: ts,
    });

    if (objectGuid) {
      await this.refreshAdResource(objectGuid, userId);
    }

    return this.rowToScimUser(
      (await this.db<ScimUserRow>('scim_users').where({ id: userId }).first())!,
    );
  }

  // ── Replace ──────────────────────────────────────────────────────────────

  async replaceUser(id: string, user: ScimUser): Promise<ScimUser> {
    const row = await this.db<ScimUserRow>('scim_users').where({ id }).first();
    if (!row) {
      throw new ScimBackendError(404, `User ${id} not found.`, 'noTarget');
    }

    const scimResource = { ...user, id };
    await this.db('scim_users').where({ id }).update({
      scim_resource: JSON.stringify(scimResource),
      sam_account_name: user.userName
        ? user.userName.split('@')[0].substring(0, 20)
        : row.sam_account_name,
      sync_status: 'pending',
      updated_at: now(),
    });

    const identity = row.ad_object_guid ?? row.sam_account_name;
    if (!identity) {
      throw new ScimBackendError(
        500,
        'Cannot identify AD account: no objectGUID or samAccountName.',
      );
    }

    const adParams = scimToAdParams(user as unknown as Record<string, unknown>);
    const { Name: _n, Path: _p, ...setParams } = adParams;

    const psResult = await execSetAdUser(identity, setParams, id);

    if (psResult.exitCode !== 0) {
      const { status, scimType, detail } = mapPsErrorToScim(psResult.stderr);
      await this.db('scim_users').where({ id }).update({
        sync_status: 'error',
        last_error: psResult.stderr.substring(0, 2000),
        updated_at: now(),
      });
      throw new ScimBackendError(status, detail, scimType);
    }

    await this.db('scim_users').where({ id }).update({
      sync_status: 'synced',
      last_error: null,
      updated_at: now(),
    });

    await this.refreshAdResource(identity, id);

    return this.rowToScimUser(
      (await this.db<ScimUserRow>('scim_users').where({ id }).first())!,
    );
  }

  // ── Patch ────────────────────────────────────────────────────────────────

  async patchUser(id: string, patch: ScimPatchOp): Promise<ScimUser> {
    const row = await this.db<ScimUserRow>('scim_users').where({ id }).first();
    if (!row) {
      throw new ScimBackendError(404, `User ${id} not found.`, 'noTarget');
    }

    const currentResource = JSON.parse(row.scim_resource) as Record<string, unknown>;
    const { updated: patchedResource, changedFields } = applyPatchOps(
      currentResource,
      patch.Operations,
    );

    await this.db('scim_users').where({ id }).update({
      scim_resource: JSON.stringify({ ...patchedResource, id }),
      sync_status: 'pending',
      updated_at: now(),
    });

    const identity = row.ad_object_guid ?? row.sam_account_name;
    if (!identity) {
      throw new ScimBackendError(
        500,
        'Cannot identify AD account: no objectGUID or samAccountName.',
      );
    }

    const adParams = scimToAdParams(changedFields);
    const { Name: _n, Path: _p, ...setParams } = adParams;

    if (Object.keys(setParams).length > 0) {
      const psResult = await execSetAdUser(identity, setParams, id);

      if (psResult.exitCode !== 0) {
        const { status, scimType, detail } = mapPsErrorToScim(psResult.stderr);
        await this.db('scim_users').where({ id }).update({
          sync_status: 'error',
          last_error: psResult.stderr.substring(0, 2000),
          updated_at: now(),
        });
        throw new ScimBackendError(status, detail, scimType);
      }
    }

    await this.db('scim_users').where({ id }).update({
      sync_status: 'synced',
      last_error: null,
      updated_at: now(),
    });

    await this.refreshAdResource(identity, id);

    return this.rowToScimUser(
      (await this.db<ScimUserRow>('scim_users').where({ id }).first())!,
    );
  }

  // ── Delete ───────────────────────────────────────────────────────────────

  async deleteUser(id: string): Promise<void> {
    const row = await this.db<ScimUserRow>('scim_users').where({ id }).first();
    if (!row) {
      throw new ScimBackendError(404, `User ${id} not found.`, 'noTarget');
    }

    const identity = row.ad_object_guid ?? row.sam_account_name;

    if (identity) {
      const psResult = await execRemoveAdUser(identity, id);

      if (psResult.exitCode !== 0) {
        const alreadyGone =
          psResult.stderr.toLowerCase().includes('cannot find') ||
          psResult.stderr.toLowerCase().includes('not found');

        if (!alreadyGone) {
          const { status, scimType, detail } = mapPsErrorToScim(psResult.stderr);
          throw new ScimBackendError(status, detail, scimType);
        }
      }
    }

    await this.db('scim_users').where({ id }).delete();
  }

  // ── Helpers ──────────────────────────────────────────────────────────────

  private rowToScimUser(row: ScimUserRow): ScimUser {
    const cached = JSON.parse(row.scim_resource) as Record<string, unknown>;
    return {
      schemas: [SCIM_SCHEMA_USER],
      id: row.id,
      externalId: (cached['externalId'] as string | undefined) ?? undefined,
      userName: (cached['userName'] as string) ?? row.sam_account_name ?? '',
      name: (cached['name'] as ScimUser['name']) ?? undefined,
      displayName: (cached['displayName'] as string | undefined) ?? undefined,
      emails: (cached['emails'] as ScimUser['emails']) ?? undefined,
      active: (cached['active'] as boolean | undefined) ?? undefined,
      meta: {
        resourceType: 'User',
        created: row.created_at,
        lastModified: row.updated_at,
      },
    };
  }

  private async refreshAdResource(identity: string, scimUserId: string): Promise<void> {
    try {
      const adUser = await execGetAdUser(identity, scimUserId);
      if (adUser) {
        await this.db('scim_users').where({ id: scimUserId }).update({
          ad_resource: JSON.stringify(adUser),
          updated_at: now(),
        });
      }
    } catch {
      // Swallow — the SCIM operation has already succeeded
    }
  }
}

function now(): string {
  return new Date().toISOString();
}
