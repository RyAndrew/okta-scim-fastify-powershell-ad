// ---------------------------------------------------------------------------
// SCIM 2.0 ↔ Active Directory attribute mapping
//
// This file is the single source of truth for how SCIM fields map to AD
// cmdlet parameters. Update this file when you need to add or change
// attribute mappings — no route code needs to change.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Parameters accepted by New-ADUser and Set-ADUser.
 * Only the attributes we explicitly map are included.
 */
export interface AdUserParams {
  /** Used as the logon name (pre-Windows 2000). Maps from SCIM userName. */
  SamAccountName?: string;
  /** Maps from SCIM name.givenName. */
  GivenName?: string;
  /** Maps from SCIM name.familyName. */
  Surname?: string;
  /** Maps from SCIM emails[primary=true].value. */
  EmailAddress?: string;
  /** Maps from SCIM displayName. */
  DisplayName?: string;
  /**
   * CN used as the display name in AD. Defaults to displayName → userName.
   * Required by New-ADUser.
   */
  Name?: string;
  /** Maps from SCIM active. */
  Enabled?: boolean;
  /** Maps from SCIM externalId (Okta user ID stored as EmployeeID). */
  EmployeeID?: string;
  /** Target OU distinguished name — only used by New-ADUser. */
  Path?: string;
  /** UPN suffix — derived from userName if it contains @. */
  UserPrincipalName?: string;
}

// ---------------------------------------------------------------------------
// SCIM → AD parameter mapping
// ---------------------------------------------------------------------------

/**
 * Maps a SCIM User resource (or partial resource from a PATCH) to
 * Active Directory cmdlet parameters.
 *
 * @param scimUser  The SCIM resource or partial changed-fields object.
 * @param baseOu    When provided, sets the `Path` parameter (New-ADUser only).
 */
export function scimToAdParams(
  scimUser: Record<string, unknown>,
  baseOu?: string,
): AdUserParams {
  const params: AdUserParams = {};

  // userName → SamAccountName (and optionally UserPrincipalName)
  const userName = scimUser['userName'] as string | undefined;
  if (userName) {
    params.SamAccountName = userName;
    if (userName.includes('@')) {
      params.UserPrincipalName = userName;
    }
  }

  // name.givenName / name.familyName
  const name = scimUser['name'] as Record<string, string | undefined> | undefined;
  if (name?.givenName) params.GivenName = name.givenName;
  if (name?.familyName) params.Surname = name.familyName;

  // emails — prefer the entry flagged as primary; fall back to index 0
  const emails = scimUser['emails'] as Array<Record<string, unknown>> | undefined;
  if (emails && emails.length > 0) {
    const primary = emails.find((e) => e['primary'] === true) ?? emails[0];
    const emailValue = primary['value'] as string | undefined;
    if (emailValue) params.EmailAddress = emailValue;
  }

  // displayName
  const displayName = scimUser['displayName'] as string | undefined;
  if (displayName) params.DisplayName = displayName;

  // active → Enabled
  const active = scimUser['active'];
  if (typeof active === 'boolean') params.Enabled = active;

  // externalId → EmployeeID (stores the Okta user ID in AD)
  const externalId = scimUser['externalId'] as string | undefined;
  if (externalId) params.EmployeeID = externalId;

  // CN for New-ADUser — required; prefer displayName then userName
  params.Name = params.DisplayName ?? params.SamAccountName;

  // Target OU (New-ADUser only)
  if (baseOu) params.Path = baseOu;

  return params;
}

// ---------------------------------------------------------------------------
// AD → SCIM partial mapping (for enriching the cached resource after a sync)
// ---------------------------------------------------------------------------

/**
 * Merges an AD user object (from `Get-ADUser -Properties *`) into an existing
 * SCIM resource, updating the fields we manage.
 */
export function mergeAdIntoScim(
  existing: Record<string, unknown>,
  adUser: Record<string, unknown>,
): Record<string, unknown> {
  const merged = { ...existing };

  if (adUser['SamAccountName']) {
    merged['userName'] = adUser['SamAccountName'];
  }
  if (adUser['DisplayName']) {
    merged['displayName'] = adUser['DisplayName'];
  }
  if (adUser['GivenName'] || adUser['Surname']) {
    merged['name'] = {
      ...(merged['name'] as Record<string, unknown> | undefined ?? {}),
      ...(adUser['GivenName'] ? { givenName: adUser['GivenName'] } : {}),
      ...(adUser['Surname'] ? { familyName: adUser['Surname'] } : {}),
    };
  }
  if (adUser['EmailAddress']) {
    merged['emails'] = [
      { value: adUser['EmailAddress'], type: 'work', primary: true },
    ];
  }
  if (typeof adUser['Enabled'] === 'boolean') {
    merged['active'] = adUser['Enabled'];
  }

  return merged;
}
