// ---------------------------------------------------------------------------
// Active Directory backend implementation
//
// Implements ScimBackend using PowerShell cmdlets for all AD operations.
// AD is the source of truth: every read queries AD directly, and the SCIM
// id is the user's objectGUID. All lookups are scoped to the configured
// base OU, so users outside it are invisible and cannot be modified.
// The local database is used only for request / PowerShell audit logging.
// ---------------------------------------------------------------------------

import {
  ScimBackend,
  ScimBackendError,
  ScimUser,
  ScimPatchOp,
  ListUsersOptions,
  ListUsersResult,
  ParsedFilter,
  applyPatchOps,
} from 'scim-fastify-core';
import {
  AdUserLookup,
  PowerShellResult,
  execFindAdUsers,
  execNewAdUser,
  execSetAdUser,
  execRemoveAdUser,
} from './powershell';
import { AdUser, adToScimUser, scimToAdParams } from './config/mapping';
import { mapPsErrorToScim } from './ps-errors';

const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// ---------------------------------------------------------------------------
// SCIM filter attribute → AD lookup
// ---------------------------------------------------------------------------

const FILTER_ATTR_TO_LOOKUP: Record<string, Exclude<AdUserLookup['by'], 'all'>> = {
  id: 'guid',
  externalid: 'employeeId',
  username: 'userName',
  emails: 'email',
  'emails.value': 'email',
};

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

export class PowerShellAdBackend implements ScimBackend {
  constructor(
    private readonly config: {
      ad: { baseOu: string; defaultPassword: string };
    },
  ) {}

  // ── List ────────────────────────────────────────────────────────────────

  async listUsers({ filter, startIndex, count }: ListUsersOptions): Promise<ListUsersResult> {
    const lookup = toLookup(filter);
    // An id filter that isn't a GUID can never match an AD user
    if (lookup.by === 'guid' && !GUID_RE.test(lookup.value)) {
      return { users: [], totalResults: 0 };
    }

    const { users, result } = await execFindAdUsers(this.config.ad.baseOu, lookup);
    if (result.exitCode !== 0) throw psError(result);

    // AD has no offset paging, so sort for a stable order and slice here
    users.sort(
      (a, b) =>
        (a.whenCreated ?? '').localeCompare(b.whenCreated ?? '') ||
        a.ObjectGUID.localeCompare(b.ObjectGUID),
    );
    const page = users.slice(startIndex - 1, startIndex - 1 + count);

    return {
      users: page.map(adToScimUser),
      totalResults: users.length,
    };
  }

  // ── Get ─────────────────────────────────────────────────────────────────

  async getUser(id: string): Promise<ScimUser> {
    return adToScimUser(await this.findAdUser(id));
  }

  // ── Create ───────────────────────────────────────────────────────────────

  async createUser(user: ScimUser): Promise<ScimUser> {
    const { users: existing, result } = await execFindAdUsers(this.config.ad.baseOu, {
      by: 'userName',
      value: user.userName,
    });
    if (result.exitCode !== 0) throw psError(result);

    if (existing.length > 0) {
      throw new ScimBackendError(
        409,
        `A user with userName '${user.userName}' already exists.`,
        'uniqueness',
      );
    }

    const adParams = scimToAdParams(
      user as unknown as Record<string, unknown>,
      this.config.ad.baseOu,
    );

    const psResult = await execNewAdUser({
      ...adParams,
      AccountPassword: this.config.ad.defaultPassword,
    });
    if (psResult.exitCode !== 0) throw psError(psResult);

    const objectGuid = typeof psResult.parsed === 'string' ? psResult.parsed : null;
    if (!objectGuid) {
      throw new ScimBackendError(500, 'New-ADUser succeeded but returned no objectGUID.');
    }

    return this.getUser(objectGuid);
  }

  // ── Replace ──────────────────────────────────────────────────────────────

  async replaceUser(id: string, user: ScimUser): Promise<ScimUser> {
    const adUser = await this.findAdUser(id);

    const adParams = scimToAdParams(user as unknown as Record<string, unknown>);
    const { Name: _n, Path: _p, ...setParams } = adParams;

    const psResult = await execSetAdUser(adUser.ObjectGUID, setParams, id);
    if (psResult.exitCode !== 0) throw psError(psResult);

    return this.getUser(id);
  }

  // ── Patch ────────────────────────────────────────────────────────────────

  async patchUser(id: string, patch: ScimPatchOp): Promise<ScimUser> {
    const adUser = await this.findAdUser(id);

    const { changedFields } = applyPatchOps(
      adToScimUser(adUser) as unknown as Record<string, unknown>,
      patch.Operations,
    );

    const adParams = scimToAdParams(changedFields);
    const { Name: _n, Path: _p, ...setParams } = adParams;

    if (Object.keys(setParams).length > 0) {
      const psResult = await execSetAdUser(adUser.ObjectGUID, setParams, id);
      if (psResult.exitCode !== 0) throw psError(psResult);
    }

    return this.getUser(id);
  }

  // ── Delete ───────────────────────────────────────────────────────────────

  async deleteUser(id: string): Promise<void> {
    const adUser = await this.findAdUser(id);

    const psResult = await execRemoveAdUser(adUser.ObjectGUID, id);
    if (psResult.exitCode !== 0) throw psError(psResult);
  }

  // ── Helpers ──────────────────────────────────────────────────────────────

  /** Look up a user by SCIM id (objectGUID) under the base OU, or throw 404. */
  private async findAdUser(id: string): Promise<AdUser> {
    if (!GUID_RE.test(id)) {
      throw new ScimBackendError(404, `User ${id} not found.`, 'noTarget');
    }

    const { users, result } = await execFindAdUsers(
      this.config.ad.baseOu,
      { by: 'guid', value: id },
      id,
    );
    if (result.exitCode !== 0) throw psError(result);

    if (users.length === 0) {
      throw new ScimBackendError(404, `User ${id} not found.`, 'noTarget');
    }
    return users[0];
  }
}

function toLookup(filter: ParsedFilter | undefined): AdUserLookup {
  if (!filter) return { by: 'all' };

  const by = FILTER_ATTR_TO_LOOKUP[filter.attribute.toLowerCase()];
  if (!by || filter.operator !== 'eq') {
    throw new ScimBackendError(
      400,
      `Unsupported filter '${filter.attribute} ${filter.operator}'. ` +
        `Only 'eq' on id, externalId, userName or emails.value is supported.`,
      'invalidFilter',
    );
  }
  return { by, value: filter.value };
}

function psError(result: PowerShellResult): ScimBackendError {
  const { status, scimType, detail } = mapPsErrorToScim(result.stderr);
  return new ScimBackendError(status, detail, scimType);
}
