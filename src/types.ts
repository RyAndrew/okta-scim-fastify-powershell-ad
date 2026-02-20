// ---------------------------------------------------------------------------
// Database row types for scim-ad-bridge
// ---------------------------------------------------------------------------

export type SyncStatus = 'synced' | 'pending' | 'error';

export interface ScimUserRow {
  id: string;
  ad_object_guid: string | null;
  sam_account_name: string | null;
  /** Full SCIM JSON as last sent by the IdP */
  scim_resource: string;
  /** Full AD JSON from Get-ADUser -Properties * */
  ad_resource: string | null;
  sync_status: SyncStatus;
  last_error: string | null;
  created_at: string;
  updated_at: string;
}
