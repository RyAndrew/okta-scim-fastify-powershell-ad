// ---------------------------------------------------------------------------
// PowerShell execution layer
//
// All Active Directory operations run through this module.  Every execution
// is printed to the console for debugging and audited to the
// powershell_executions table.
//
// Design decisions:
//   - execFile("powershell.exe") rather than exec() to avoid shell injection.
//   - $ErrorActionPreference = 'Stop' ensures non-terminating errors also
//     surface as exceptions that map to a non-zero exit code.
//   - Import-Module ActiveDirectory is explicit so the script works when
//     the PS session doesn't auto-load the module.
//   - Secrets are passed to the child process via environment variables, so
//     the script text never contains them and is safe to print and log.
// ---------------------------------------------------------------------------

import { execFile } from 'child_process';
import { promisify } from 'util';
import { db } from './db';
import { AdUser, AdUserParams } from './config/mapping';

const execFileAsync = promisify(execFile);

const CONSOLE_OUTPUT_LIMIT = 4_000;

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

export interface PowerShellResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  durationMs: number;
  /** Parsed JSON from stdout, or raw stdout string if JSON parsing failed. */
  parsed: unknown;
}

// ---------------------------------------------------------------------------
// Low-level executor
// ---------------------------------------------------------------------------

/**
 * Execute an arbitrary PowerShell script, print it to the console and log
 * the result.
 *
 * @param script      The full PS script to run (multi-line OK). Must not
 *                    contain secrets — pass those through `env` instead.
 * @param logMeta     Metadata written to the audit log row.
 * @param env         Extra environment variables for the child process.
 */
export async function executePowerShell(
  script: string,
  logMeta: {
    cmdlet: string;
    params: Record<string, unknown>;
    scimUserId?: string;
  },
  env: Record<string, string> = {},
): Promise<PowerShellResult> {
  const startTime = Date.now();
  let stdout = '';
  let stderr = '';
  let exitCode = 0;
  let parsed: unknown = null;

  const label = `[PS] ${logMeta.cmdlet}${logMeta.scimUserId ? ` (user ${logMeta.scimUserId})` : ''}`;
  console.log(`${label} executing:\n${script}\n`);

  try {
    const result = await execFileAsync(
      'powershell.exe',
      ['-NonInteractive', '-NoProfile', '-Command', script],
      {
        maxBuffer: 10 * 1024 * 1024,
        timeout: 30_000,
        env: { ...process.env, ...env },
      },
    );
    stdout = result.stdout ?? '';
    stderr = result.stderr ?? '';
    exitCode = 0;
  } catch (err: unknown) {
    const execErr = err as { stdout?: string; stderr?: string; code?: number };
    stdout = execErr.stdout ?? '';
    stderr = execErr.stderr ?? String(err);
    exitCode = typeof execErr.code === 'number' ? execErr.code : 1;
  }

  const durationMs = Date.now() - startTime;

  console.log(`${label} exit ${exitCode} in ${durationMs}ms`);
  if (stderr.trim()) console.log(`${label} stderr:\n${truncate(stderr.trim())}`);
  if (stdout.trim()) console.log(`${label} stdout:\n${truncate(stdout.trim())}`);

  if (stdout.trim()) {
    try {
      parsed = JSON.parse(stdout.trim());
    } catch {
      parsed = stdout.trim();
    }
  }

  // Audit log — fire-and-forget; never block the caller
  db('powershell_executions')
    .insert({
      cmdlet: logMeta.cmdlet,
      // Strip password values from the logged params
      parameters: JSON.stringify(sanitizeParams(logMeta.params)),
      stdout: stdout.substring(0, 65_535),
      stderr: stderr.substring(0, 65_535),
      exit_code: exitCode,
      duration_ms: durationMs,
      scim_user_id: logMeta.scimUserId ?? null,
    })
    .catch((e: Error) => console.error('[PS audit] DB write failed:', e.message));

  return { stdout, stderr, exitCode, durationMs, parsed };
}

function truncate(text: string): string {
  return text.length > CONSOLE_OUTPUT_LIMIT
    ? `${text.substring(0, CONSOLE_OUTPUT_LIMIT)}... (${text.length - CONSOLE_OUTPUT_LIMIT} more chars)`
    : text;
}

// ---------------------------------------------------------------------------
// Script builders — one per AD operation
// ---------------------------------------------------------------------------

const PS_HEADER = `
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
`.trimStart();

/**
 * Escape a string value for safe embedding inside single-quoted PS strings.
 * Single quotes are doubled per PS escaping rules.
 */
function esc(value: string): string {
  return value.replace(/'/g, "''");
}

/**
 * Render a boolean as a PowerShell literal.
 */
function psBool(value: boolean): string {
  return value ? '$true' : '$false';
}

/**
 * Build -Key:'value' fragments for string params and -Key:$bool for booleans.
 * Skips undefined/null values.
 * Certain keys (Password, Path, Identity, Name) are handled by callers.
 */
function buildParamFragments(
  params: Record<string, unknown>,
  skip: string[] = [],
): string {
  const skipSet = new Set(skip.map((s) => s.toLowerCase()));
  const parts: string[] = [];

  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null) continue;
    if (skipSet.has(key.toLowerCase())) continue;

    if (typeof value === 'boolean') {
      parts.push(`-${key}:${psBool(value)}`);
    } else {
      parts.push(`-${key} '${esc(String(value))}'`);
    }
  }

  return parts.join(' ');
}

// ---------------------------------------------------------------------------
// Get-ADUser (search)
// ---------------------------------------------------------------------------

/** How to locate users in AD. Every lookup is scoped to the search base. */
export type AdUserLookup =
  | { by: 'all' }
  | { by: 'guid'; value: string }
  /** Matches UserPrincipalName or SamAccountName exactly. */
  | { by: 'userName'; value: string }
  | { by: 'employeeId'; value: string }
  | { by: 'email'; value: string };

/** Extra properties beyond Get-ADUser's defaults that AdUser needs. */
const AD_EXTRA_PROPERTIES = 'DisplayName,EmailAddress,EmployeeID,whenCreated,whenChanged';

/**
 * Projects ADUser objects onto the flat AdUser shape. GUIDs and dates are
 * converted to strings explicitly because ConvertTo-Json serialises them
 * differently across PowerShell versions.
 */
const AD_USER_SELECT = [
  "@{n='ObjectGUID';e={$_.ObjectGUID.ToString()}}",
  'SamAccountName',
  'UserPrincipalName',
  'GivenName',
  'Surname',
  'DisplayName',
  'EmailAddress',
  'EmployeeID',
  'Enabled',
  'DistinguishedName',
  "@{n='whenCreated';e={$_.whenCreated.ToUniversalTime().ToString('o')}}",
  "@{n='whenChanged';e={$_.whenChanged.ToUniversalTime().ToString('o')}}",
].join(', ');

/**
 * Build the `$value = ...` assignment and -Filter expression for a lookup.
 * The filter references $value rather than embedding the literal, so the
 * AD filter parser never sees user-supplied text.
 */
function buildLookupFilter(lookup: AdUserLookup): { assignment: string; filter: string } {
  switch (lookup.by) {
    case 'all':
      return { assignment: '', filter: '*' };
    case 'guid':
      return { assignment: `$value = [guid]'${esc(lookup.value)}'`, filter: "'ObjectGUID -eq $value'" };
    case 'userName':
      return {
        assignment: `$value = '${esc(lookup.value)}'`,
        filter: "'UserPrincipalName -eq $value -or SamAccountName -eq $value'",
      };
    case 'employeeId':
      return { assignment: `$value = '${esc(lookup.value)}'`, filter: "'EmployeeID -eq $value'" };
    case 'email':
      return { assignment: `$value = '${esc(lookup.value)}'`, filter: "'mail -eq $value'" };
  }
}

/**
 * Search AD for users under `searchBase`.
 * Check `result.exitCode` for failure; `users` is empty when nothing matches.
 */
export async function execFindAdUsers(
  searchBase: string,
  lookup: AdUserLookup,
  scimUserId?: string,
): Promise<{ users: AdUser[]; result: PowerShellResult }> {
  const { assignment, filter } = buildLookupFilter(lookup);

  const script = `
${PS_HEADER}
${assignment}
$users = @(Get-ADUser -SearchBase '${esc(searchBase)}' -Filter ${filter} -Properties ${AD_EXTRA_PROPERTIES})
ConvertTo-Json -Depth 3 -Compress -InputObject @($users | Select-Object ${AD_USER_SELECT})
`.trim();

  const result = await executePowerShell(script, {
    cmdlet: 'Get-ADUser',
    params: { searchBase, ...lookup },
    scimUserId,
  });

  if (result.exitCode !== 0) return { users: [], result };

  const parsed = result.parsed;
  const users = Array.isArray(parsed)
    ? parsed
    : parsed && typeof parsed === 'object'
      ? [parsed]
      : [];
  return { users: users as AdUser[], result };
}

// ---------------------------------------------------------------------------
// New-ADUser
// ---------------------------------------------------------------------------

export interface NewAdUserScriptParams extends AdUserParams {
  /** Required by AD. Passed via environment variable. Never logged. */
  AccountPassword: string;
}

/**
 * Create a new AD user. On success `parsed` is the new user's ObjectGUID string.
 */
export async function execNewAdUser(params: NewAdUserScriptParams): Promise<PowerShellResult> {
  const { AccountPassword, Name, Path, SamAccountName, ...rest } = params;

  // Build the static-param fragments (everything except password and params
  // already injected inline: Name, Path, SamAccountName, AccountPassword)
  const fragments = buildParamFragments(rest as Record<string, unknown>);

  const script = `
${PS_HEADER}
$password = ConvertTo-SecureString -String $env:SCIM_AD_ACCOUNT_PASSWORD -AsPlainText -Force
$user = New-ADUser \`
  -Name '${esc(Name ?? SamAccountName ?? '')}' \`
  ${SamAccountName ? `-SamAccountName '${esc(SamAccountName)}' \`` : ''}
  -AccountPassword $password \`
  -ChangePasswordAtLogon:$false \`
  ${Path ? `-Path '${esc(Path)}' \`` : ''}
  ${fragments} \`
  -PassThru
ConvertTo-Json -Compress -InputObject $user.ObjectGUID.ToString()
`.trim();

  return executePowerShell(
    script,
    {
      cmdlet: 'New-ADUser',
      params: { Name, Path, SamAccountName, ...rest },
    },
    { SCIM_AD_ACCOUNT_PASSWORD: AccountPassword },
  );
}

// ---------------------------------------------------------------------------
// Set-ADUser
// ---------------------------------------------------------------------------

/**
 * Modify an existing AD user.  Only the supplied attributes are changed.
 */
export async function execSetAdUser(
  identity: string,
  params: Omit<AdUserParams, 'Name' | 'Path'>,
  scimUserId: string,
): Promise<PowerShellResult> {
  const fragments = buildParamFragments(params as Record<string, unknown>);

  const script = `
${PS_HEADER}
Set-ADUser -Identity '${esc(identity)}' ${fragments}
`.trim();

  return executePowerShell(script, {
    cmdlet: 'Set-ADUser',
    params: { identity, ...params } as Record<string, unknown>,
    scimUserId,
  });
}

// ---------------------------------------------------------------------------
// Remove-ADUser
// ---------------------------------------------------------------------------

/**
 * Delete an AD user.  Uses -Confirm:$false to suppress interactive prompts.
 */
export async function execRemoveAdUser(
  identity: string,
  scimUserId: string,
): Promise<PowerShellResult> {
  const script = `
${PS_HEADER}
Remove-ADUser -Identity '${esc(identity)}' -Confirm:$false
`.trim();

  return executePowerShell(script, {
    cmdlet: 'Remove-ADUser',
    params: { identity },
    scimUserId,
  });
}

// ---------------------------------------------------------------------------
// Security helpers
// ---------------------------------------------------------------------------

const SENSITIVE_KEYS = new Set(['accountpassword', 'password', 'secret', 'token']);

function sanitizeParams(params: Record<string, unknown>): Record<string, unknown> {
  const safe: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(params)) {
    safe[key] = SENSITIVE_KEYS.has(key.toLowerCase()) ? '***REDACTED***' : value;
  }
  return safe;
}
