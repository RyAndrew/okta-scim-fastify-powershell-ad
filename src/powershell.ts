// ---------------------------------------------------------------------------
// PowerShell execution layer
//
// All Active Directory operations run through this module.  Every execution
// is automatically audited to the powershell_executions table.
//
// Design decisions:
//   - execFile("powershell.exe") rather than exec() to avoid shell injection.
//   - $ErrorActionPreference = 'Stop' ensures non-terminating errors also
//     surface as exceptions that map to a non-zero exit code.
//   - Import-Module ActiveDirectory is explicit so the script works when
//     the PS session doesn't auto-load the module.
//   - ConvertTo-Json is applied only for cmdlets that produce output.
//   - Passwords are never logged.
// ---------------------------------------------------------------------------

import { execFile } from 'child_process';
import { promisify } from 'util';
import { db } from './db';
import { AdUserParams } from './config/mapping';

const execFileAsync = promisify(execFile);

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
 * Execute an arbitrary PowerShell script and log the result.
 *
 * @param script      The full PS script to run (multi-line OK).
 * @param logMeta     Metadata written to the audit log row.
 */
export async function executePowerShell(
  script: string,
  logMeta: {
    cmdlet: string;
    params: Record<string, unknown>;
    scimUserId?: string;
  },
): Promise<PowerShellResult> {
  const startTime = Date.now();
  let stdout = '';
  let stderr = '';
  let exitCode = 0;
  let parsed: unknown = null;

  try {
    const result = await execFileAsync(
      'powershell.exe',
      ['-NonInteractive', '-NoProfile', '-Command', script],
      { maxBuffer: 10 * 1024 * 1024, timeout: 30_000 },
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
// New-ADUser
// ---------------------------------------------------------------------------

export interface NewAdUserScriptParams extends AdUserParams {
  /** Required by AD. Passed as a SecureString. Never logged. */
  AccountPassword: string;
}

/**
 * Create a new AD user and return the created object as parsed JSON.
 */
export async function execNewAdUser(
  params: NewAdUserScriptParams,
  scimUserId: string,
): Promise<PowerShellResult> {
  const { AccountPassword, Name, Path, SamAccountName, ...rest } = params;

  // Build the static-param fragments (everything except password)
  const adParams: Record<string, unknown> = { ...rest };
  if (SamAccountName) adParams['SamAccountName'] = SamAccountName;

  const fragments = buildParamFragments(adParams);

  const script = `
${PS_HEADER}
$password = ConvertTo-SecureString -String '${esc(AccountPassword)}' -AsPlainText -Force
New-ADUser \`
  -Name '${esc(Name ?? SamAccountName ?? '')}' \`
  ${SamAccountName ? `-SamAccountName '${esc(SamAccountName)}' \`` : ''}
  -AccountPassword $password \`
  -ChangePasswordAtLogon:$false \`
  ${Path ? `-Path '${esc(Path)}' \`` : ''}
  ${fragments} \`
  -PassThru |
  ConvertTo-Json -Depth 5 -Compress
`.trim();

  return executePowerShell(script, {
    cmdlet: 'New-ADUser',
    // Exclude the password from the logged params
    params: sanitizeParams({ Name, Path, SamAccountName, ...rest }),
    scimUserId,
  });
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
// Get-ADUser
// ---------------------------------------------------------------------------

/**
 * Read a user from AD and return the full attribute set as a parsed object.
 * Returns `null` when the user does not exist or PowerShell fails.
 */
export async function execGetAdUser(
  identity: string,
  scimUserId?: string,
): Promise<Record<string, unknown> | null> {
  const script = `
${PS_HEADER}
Get-ADUser -Identity '${esc(identity)}' -Properties * |
  ConvertTo-Json -Depth 5 -Compress
`.trim();

  const result = await executePowerShell(script, {
    cmdlet: 'Get-ADUser',
    params: { identity },
    scimUserId,
  });

  if (result.exitCode !== 0 || !result.parsed) return null;
  return result.parsed as Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// ObjectGUID extraction helper
// ---------------------------------------------------------------------------

/**
 * Extract the objectGUID string from a parsed `Get-ADUser` / `New-ADUser -PassThru` result.
 * PowerShell serialises Guid objects in various ways across PS versions.
 */
export function extractObjectGuid(parsed: unknown): string | null {
  if (!parsed || typeof parsed !== 'object') return null;
  const obj = parsed as Record<string, unknown>;

  // PS 5.1 / 7: "ObjectGUID": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  const raw = obj['ObjectGUID'];
  if (typeof raw === 'string' && raw.length > 0) return raw;

  // Some versions wrap it: { "value": "..." }
  if (raw && typeof raw === 'object') {
    const wrapped = raw as Record<string, unknown>;
    if (typeof wrapped['value'] === 'string') return wrapped['value'];
  }

  return null;
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
