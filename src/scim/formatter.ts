import {
  ScimUser,
  ScimListResponse,
  ScimError,
  ScimUserRow,
  SCIM_SCHEMA_USER,
  SCIM_SCHEMA_LIST,
  SCIM_SCHEMA_ERROR,
} from './types';

// ---------------------------------------------------------------------------
// Build a fully-conformant SCIM User resource from a DB row
// ---------------------------------------------------------------------------

export function formatScimUser(row: ScimUserRow, baseUrl: string): ScimUser {
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
      location: `${baseUrl}/scim/v2/Users/${row.id}`,
    },
  };
}

// ---------------------------------------------------------------------------
// Build a SCIM ListResponse envelope
// ---------------------------------------------------------------------------

export function formatListResponse(
  users: ScimUser[],
  totalResults: number,
  startIndex: number,
): ScimListResponse<ScimUser> {
  return {
    schemas: [SCIM_SCHEMA_LIST],
    totalResults,
    startIndex,
    itemsPerPage: users.length,
    Resources: users,
  };
}

// ---------------------------------------------------------------------------
// Build a SCIM Error response
// ---------------------------------------------------------------------------

export function formatError(
  status: number,
  detail: string,
  scimType?: string,
): ScimError {
  return {
    schemas: [SCIM_SCHEMA_ERROR],
    status,
    ...(scimType ? { scimType } : {}),
    detail,
  };
}

// ---------------------------------------------------------------------------
// Map a PowerShell error message to an appropriate HTTP status + SCIM type
// ---------------------------------------------------------------------------

export function mapPsErrorToScim(
  stderr: string,
): { status: number; scimType?: string; detail: string } {
  const msg = stderr.toLowerCase();

  if (msg.includes('already exists') || msg.includes('already in use')) {
    return { status: 409, scimType: 'uniqueness', detail: stderr };
  }
  if (
    msg.includes('cannot find an object with identity') ||
    msg.includes('not found') ||
    msg.includes('no such object')
  ) {
    return { status: 404, scimType: 'noTarget', detail: stderr };
  }
  if (
    msg.includes('password') &&
    (msg.includes('complexity') || msg.includes('length') || msg.includes('requirement'))
  ) {
    return { status: 400, scimType: 'invalidValue', detail: stderr };
  }
  if (msg.includes('access') && msg.includes('denied')) {
    return { status: 403, detail: stderr };
  }
  if (msg.includes('invalid') || msg.includes('bad request')) {
    return { status: 400, scimType: 'invalidValue', detail: stderr };
  }

  return { status: 500, detail: stderr };
}
