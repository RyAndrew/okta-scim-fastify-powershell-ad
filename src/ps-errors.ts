/**
 * Maps a PowerShell stderr message to an HTTP status code and optional
 * SCIM error type.
 */
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
