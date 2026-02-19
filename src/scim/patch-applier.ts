// ---------------------------------------------------------------------------
// SCIM 2.0 PATCH operation applier (RFC 7644 §3.5.2)
//
// Handles the common patterns sent by Okta:
//   { op: "replace", path: "active", value: false }
//   { op: "replace", value: { active: false, displayName: "..." } }
//   { op: "add",     path: "emails[type eq \"work\"].value", value: "..." }
//
// Complex multi-valued path expressions are parsed with a best-effort
// approach that covers the real-world Okta patterns without requiring a
// full SCIM path grammar implementation.
// ---------------------------------------------------------------------------

import { PatchOperation } from './types';

export interface ApplyPatchResult {
  /** The mutated resource (a new object, does not mutate the original). */
  updated: Record<string, unknown>;
  /** Only the top-level fields that were modified — used to build AD params. */
  changedFields: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

export function applyPatchOps(
  resource: Record<string, unknown>,
  operations: PatchOperation[],
): ApplyPatchResult {
  const updated: Record<string, unknown> = { ...resource };
  const changedFields: Record<string, unknown> = {};

  for (const op of operations) {
    applyOp(updated, changedFields, op);
  }

  return { updated, changedFields };
}

// ---------------------------------------------------------------------------
// Single operation dispatch
// ---------------------------------------------------------------------------

function applyOp(
  resource: Record<string, unknown>,
  changed: Record<string, unknown>,
  op: PatchOperation,
): void {
  const verb = op.op.toLowerCase() as 'add' | 'remove' | 'replace';

  if (!op.path) {
    // No path → value is an object of attribute:value pairs (bulk replace)
    if (verb === 'add' || verb === 'replace') {
      const values = op.value as Record<string, unknown>;
      for (const [key, val] of Object.entries(values)) {
        resource[key] = val;
        changed[key] = val;
      }
    }
    return;
  }

  // Resolve the path and apply the mutation
  const { topLevelKey } = applyPath(resource, changed, op.path, verb, op.value);
  if (topLevelKey) {
    changed[topLevelKey] = resource[topLevelKey];
  }
}

// ---------------------------------------------------------------------------
// Path resolution
// ---------------------------------------------------------------------------

interface PathResult {
  topLevelKey: string | null;
}

/**
 * Applies a value mutation at `path` within `resource`.
 * Returns the top-level key that was affected so the caller can record it
 * in `changed`.
 */
function applyPath(
  resource: Record<string, unknown>,
  _changed: Record<string, unknown>,
  path: string,
  verb: 'add' | 'remove' | 'replace',
  value: unknown,
): PathResult {
  // Simple attribute path: "active", "displayName", "userName", etc.
  if (!path.includes('.') && !path.includes('[')) {
    const key = path;
    if (verb === 'remove') {
      delete resource[key];
    } else {
      resource[key] = value;
    }
    return { topLevelKey: key };
  }

  // Multi-valued attribute path: "emails[type eq "work"].value"
  const mvMatch = /^(\w+)\[([^\]]+)\](?:\.(\w+))?$/.exec(path);
  if (mvMatch) {
    const [, attrName, filterExpr, subAttr] = mvMatch;
    const arr = (resource[attrName] as Record<string, unknown>[] | undefined) ?? [];

    if (verb === 'remove') {
      resource[attrName] = arr.filter((item) => !matchesFilter(item, filterExpr));
    } else {
      const target = arr.find((item) => matchesFilter(item, filterExpr));
      if (target && subAttr) {
        // Replace a specific sub-attribute on the matched element
        target[subAttr] = value;
        resource[attrName] = arr;
      } else if (!target) {
        // No existing element matched — add a new one
        const newItem = buildItemFromFilter(filterExpr);
        if (subAttr) newItem[subAttr] = value;
        else Object.assign(newItem, value as Record<string, unknown>);
        resource[attrName] = [...arr, newItem];
      } else {
        // Replace the entire matched element
        const idx = arr.indexOf(target);
        arr[idx] = { ...target, ...(value as Record<string, unknown>) };
        resource[attrName] = arr;
      }
    }
    return { topLevelKey: attrName };
  }

  // Dotted path: "name.givenName"
  const parts = path.split('.');
  if (parts.length === 2) {
    const [parent, child] = parts;
    const parentObj = ((resource[parent] as Record<string, unknown>) ?? {});
    if (verb === 'remove') {
      delete parentObj[child];
    } else {
      parentObj[child] = value;
    }
    resource[parent] = parentObj;
    return { topLevelKey: parent };
  }

  // Fallback: treat as simple key
  if (verb === 'remove') {
    delete resource[path];
  } else {
    resource[path] = value;
  }
  return { topLevelKey: path };
}

// ---------------------------------------------------------------------------
// Helpers for multi-valued filter expressions
// ---------------------------------------------------------------------------

/**
 * Very lightweight filter evaluator for expressions like:
 *   type eq "work"
 *   primary eq true
 */
function matchesFilter(item: Record<string, unknown>, filterExpr: string): boolean {
  const m = /^(\w+)\s+eq\s+"?([^"]*)"?$/.exec(filterExpr.trim());
  if (!m) return false;
  const [, attr, val] = m;
  const itemVal = item[attr];
  // Handle boolean strings
  if (val === 'true') return itemVal === true;
  if (val === 'false') return itemVal === false;
  return String(itemVal) === val;
}

/**
 * Construct a minimal new item object that satisfies the filter expression.
 * e.g. "type eq \"work\"" → { type: "work" }
 */
function buildItemFromFilter(filterExpr: string): Record<string, unknown> {
  const m = /^(\w+)\s+eq\s+"?([^"]*)"?$/.exec(filterExpr.trim());
  if (!m) return {};
  const [, attr, val] = m;
  return { [attr]: val };
}
