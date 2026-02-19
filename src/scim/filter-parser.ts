// ---------------------------------------------------------------------------
// Minimal SCIM 2.0 filter parser (RFC 7644 §3.4.2.2)
//
// Supports the subset of filter expressions that Okta sends:
//   userName eq "john.doe@example.com"
//   externalId eq "00u123456"
//   id eq "some-uuid"
//
// More complex filters (and, or, not, parentheses, multi-valued attr paths)
// are passed through as-is. Extension is straightforward.
// ---------------------------------------------------------------------------

export type FilterOperator = 'eq' | 'ne' | 'co' | 'sw' | 'ew' | 'pr' | 'gt' | 'ge' | 'lt' | 'le';

export interface ParsedFilter {
  attribute: string;
  operator: FilterOperator;
  value: string;
  /** Column name in the scim_users table that corresponds to this attribute */
  dbColumn: string;
}

// Maps well-known SCIM attributes to scim_users columns that can be queried
// without parsing the JSON blob.
const ATTRIBUTE_TO_COLUMN: Record<string, string> = {
  id: 'id',
  externalid: 'id',             // externalId is stored as the primary key
  username: 'sam_account_name',
};

const FILTER_RE =
  /^(\S+)\s+(eq|ne|co|sw|ew|pr|gt|ge|lt|le)\s+"([^"]*)"$/i;

/**
 * Parse a simple SCIM filter expression.
 * Returns `null` for complex filters or unsupported attributes.
 */
export function parseScimFilter(filter: string): ParsedFilter | null {
  const match = FILTER_RE.exec(filter.trim());
  if (!match) return null;

  const [, attribute, operatorRaw, value] = match;
  const operator = operatorRaw.toLowerCase() as FilterOperator;
  const dbColumn = ATTRIBUTE_TO_COLUMN[attribute.toLowerCase()];

  if (!dbColumn) {
    // Attribute doesn't have a dedicated column — caller falls back to
    // scanning scim_resource JSON or performing a PowerShell query.
    return null;
  }

  return { attribute, operator, value, dbColumn };
}
