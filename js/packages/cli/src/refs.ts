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

const SECRET_FIELDS = new Set(["secret", "value", "content"]);

/**
 * Metadata view of an entry: everything an agent may see by default.
 * Secret-bearing fields are replaced by presence flags.
 */
export function entryMetadata(id: string, entry: Entry): Record<string, unknown> {
  const out: Record<string, unknown> = { id, ref: refFor(id) };
  for (const [k, v] of Object.entries(entry)) {
    if (SECRET_FIELDS.has(k)) {
      out[`has_${k}`] = true;
      continue;
    }
    out[k] = v;
  }
  return out;
}
