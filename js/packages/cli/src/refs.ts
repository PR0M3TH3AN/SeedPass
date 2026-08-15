/**
 * Entry references — the agent-safe way to address vault entries.
 *
 * A reference (`sp://entry/<id>`) carries no secret material and is safe to
 * store in agent context, transcripts, scripts, and job templates. All
 * default CLI output speaks in references and metadata; plaintext egress is
 * a separate explicit operation (plan section 9.3).
 */

import type { Entry, VaultIndex } from "@seedpass/core";

export const REF_PREFIX = "sp://entry/";

export function refFor(id: string): string {
  return REF_PREFIX + id;
}

export function parseRef(ref: string): string | null {
  if (ref.startsWith(REF_PREFIX)) {
    const id = ref.slice(REF_PREFIX.length);
    return id.length > 0 ? id : null;
  }
  return null;
}

export interface ResolvedEntry {
  id: string;
  ref: string;
  entry: Entry;
}

/** Resolve a ref, bare id, or exact label to a single entry. */
export function resolveEntry(index: VaultIndex, refOrQuery: string): ResolvedEntry {
  const byId = (id: string): ResolvedEntry | null => {
    const entry = index.entries[id];
    return entry ? { id, ref: refFor(id), entry } : null;
  };

  const refId = parseRef(refOrQuery);
  if (refId !== null) {
    const hit = byId(refId);
    if (!hit) throw new Error(`no entry for reference ${refOrQuery}`);
    return hit;
  }
  if (/^\d+$/.test(refOrQuery)) {
    const hit = byId(refOrQuery);
    if (hit) return hit;
  }
  const labelHits = Object.entries(index.entries).filter(
    ([, e]) => e.label === refOrQuery,
  );
  if (labelHits.length === 1) {
    const [id, entry] = labelHits[0]!;
    return { id, ref: refFor(id), entry };
  }
  if (labelHits.length > 1) {
    throw new Error(
      `label "${refOrQuery}" is ambiguous (${labelHits.length} entries); use an id or sp:// reference`,
    );
  }
  throw new Error(`no entry matches "${refOrQuery}"`);
}

/**
 * Fields safe to expose. An allowlist, not a denylist: entry schemas are
 * deliberately loose, so a secret-bearing field added by a newer writer (or
 * by the Python side) would otherwise pass straight through a denylist.
 */
const VISIBLE_FIELDS = new Set([
  "type",
  "kind",
  "label",
  "archived",
  "date_added",
  "date_modified",
  "modified_ts",
  "notes",
  "tags",
  "links",
  "origin",
  "index",
  "length",
  "gen_version",
  "username",
  "url",
  "period",
  "digits",
  "deterministic",
  "word_count",
  "fingerprint",
  "file_type",
  "key",
  "key_type",
  "user_id",
  "policy",
]);

/** Fields whose presence is reported but whose value never is. */
const SECRET_FIELDS = new Set(["secret", "value", "content"]);

/**
 * Custom fields carry user-defined values, and Python masks the ones marked
 * `is_hidden`. Their labels are useful metadata; their values are not ours
 * to hand out.
 */
function redactCustomFields(value: unknown): unknown {
  if (!Array.isArray(value)) return [];
  return value.map((field) => {
    if (typeof field !== "object" || field === null) return {};
    const f = field as Record<string, unknown>;
    return {
      label: f["label"],
      is_hidden: Boolean(f["is_hidden"]),
      has_value: f["value"] !== undefined && f["value"] !== "",
    };
  });
}

/**
 * Metadata view of an entry: everything an agent may see by default.
 * Secret-bearing fields are replaced by presence flags.
 */
export function entryMetadata(id: string, entry: Entry): Record<string, unknown> {
  const out: Record<string, unknown> = { id, ref: refFor(id) };
  for (const [k, v] of Object.entries(entry)) {
    if (SECRET_FIELDS.has(k)) {
      out[`has_${k}`] = v !== undefined && v !== "";
      continue;
    }
    if (k === "custom_fields") {
      out[k] = redactCustomFields(v);
      continue;
    }
    // Anything not explicitly known to be non-secret is reported as present
    // rather than shown.
    if (VISIBLE_FIELDS.has(k)) out[k] = v;
    else out[`has_${k}`] = true;
  }
  return out;
}
