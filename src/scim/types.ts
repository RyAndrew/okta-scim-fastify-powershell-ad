// ---------------------------------------------------------------------------
// SCIM 2.0 core type definitions (RFC 7644 / RFC 7643)
// ---------------------------------------------------------------------------

export const SCIM_SCHEMA_USER = 'urn:ietf:params:scim:schemas:core:2.0:User';
export const SCIM_SCHEMA_LIST = 'urn:ietf:params:scim:api:messages:2.0:ListResponse';
export const SCIM_SCHEMA_ERROR = 'urn:ietf:params:scim:api:messages:2.0:Error';
export const SCIM_SCHEMA_PATCH_OP = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';

// ---------------------------------------------------------------------------
// Sync status
// ---------------------------------------------------------------------------

export type SyncStatus = 'synced' | 'pending' | 'error';

// ---------------------------------------------------------------------------
// SCIM resource sub-types
// ---------------------------------------------------------------------------

export interface ScimName {
  formatted?: string;
  familyName?: string;
  givenName?: string;
  middleName?: string;
  honorificPrefix?: string;
  honorificSuffix?: string;
}

export interface ScimEmail {
  value: string;
  display?: string;
  type?: string;
  primary?: boolean;
}

export interface ScimMeta {
  resourceType: string;
  created?: string;
  lastModified?: string;
  location?: string;
  version?: string;
}

// ---------------------------------------------------------------------------
// SCIM User resource (RFC 7643 §4.1)
// ---------------------------------------------------------------------------

export interface ScimUser {
  schemas: string[];
  id: string;
  externalId?: string;
  userName: string;
  name?: ScimName;
  displayName?: string;
  nickName?: string;
  profileUrl?: string;
  title?: string;
  userType?: string;
  preferredLanguage?: string;
  locale?: string;
  timezone?: string;
  active?: boolean;
  password?: string;
  emails?: ScimEmail[];
  meta?: ScimMeta;
}

// ---------------------------------------------------------------------------
// SCIM List response
// ---------------------------------------------------------------------------

export interface ScimListResponse<T> {
  schemas: string[];
  totalResults: number;
  startIndex: number;
  itemsPerPage: number;
  Resources: T[];
}

// ---------------------------------------------------------------------------
// SCIM Error response
// ---------------------------------------------------------------------------

export interface ScimError {
  schemas: string[];
  status: number;
  scimType?: string;
  detail: string;
}

// ---------------------------------------------------------------------------
// SCIM Patch operation
// ---------------------------------------------------------------------------

export type PatchOpVerb = 'add' | 'remove' | 'replace';

export interface PatchOperation {
  op: PatchOpVerb;
  path?: string;
  value?: unknown;
}

export interface ScimPatchOp {
  schemas: string[];
  Operations: PatchOperation[];
}

// ---------------------------------------------------------------------------
// DB row shape for scim_users table
// ---------------------------------------------------------------------------

export interface ScimUserRow {
  id: string;
  ad_object_guid: string | null;
  sam_account_name: string | null;
  scim_resource: string;    // JSON text — the SCIM resource as last sent by IdP
  ad_resource: string | null; // JSON text — the AD user as last read by Get-ADUser
  sync_status: SyncStatus;
  last_error: string | null;
  created_at: string;
  updated_at: string;
}
