// ---------------------------------------------------------------------------
// SCIM 2.0 ↔ Active Directory attribute mapping
//
// This file is the single source of truth for how SCIM fields map to AD
// cmdlet parameters. Update this file when you need to add or change
// attribute mappings — no route code needs to change.
// ---------------------------------------------------------------------------

import { ScimUser, SCIM_SCHEMA_USER } from 'scim-fastify-core';

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
    params.SamAccountName = userName.split('@')[0].substring(0, 20);
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

  // CN for New-ADUser — first + last, falling back to displayName then SamAccountName
  const fullName =
    name?.givenName && name?.familyName
      ? `${name.givenName} ${name.familyName}`
      : undefined;
  params.Name = fullName ?? params.DisplayName ?? params.SamAccountName;

  // Target OU (New-ADUser only)
  if (baseOu) params.Path = baseOu;

  return params;
}

// ---------------------------------------------------------------------------
// AD → SCIM mapping
// ---------------------------------------------------------------------------

/**
 * A user as returned by `execFindAdUsers` — the Get-ADUser properties we
 * project, with GUIDs and dates already converted to strings.
 */
export interface AdUser {
  ObjectGUID: string;
  SamAccountName: string;
  UserPrincipalName: string | null;
  GivenName: string | null;
  Surname: string | null;
  DisplayName: string | null;
  EmailAddress: string | null;
  EmployeeID: string | null;
  Enabled: boolean;
  DistinguishedName: string;
  whenCreated: string | null;
  whenChanged: string | null;
}

/**
 * Converts an AD user into a SCIM User resource. The SCIM id is the
 * AD objectGUID; userName is the UPN when set, else the SamAccountName.
 */
export function adToScimUser(adUser: AdUser): ScimUser {
  const name =
    adUser.GivenName || adUser.Surname
      ? {
          ...(adUser.GivenName ? { givenName: adUser.GivenName } : {}),
          ...(adUser.Surname ? { familyName: adUser.Surname } : {}),
        }
      : undefined;

  return {
    schemas: [SCIM_SCHEMA_USER],
    id: adUser.ObjectGUID,
    externalId: adUser.EmployeeID ?? undefined,
    userName: adUser.UserPrincipalName ?? adUser.SamAccountName,
    name,
    displayName: adUser.DisplayName ?? undefined,
    emails: adUser.EmailAddress
      ? [{ value: adUser.EmailAddress, type: 'work', primary: true }]
      : undefined,
    active: adUser.Enabled,
    meta: {
      resourceType: 'User',
      created: adUser.whenCreated ?? undefined,
      lastModified: adUser.whenChanged ?? undefined,
    },
  };
}
