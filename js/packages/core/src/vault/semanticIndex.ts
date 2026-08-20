/**
 * Local retrieval index over entry metadata — parity with
 * src/seedpass/core/semantic_index.py.
 *
 * Despite the name this is not vector search and needs no model: it tokenizes
 * an entry's descriptive fields and scores a query by Jaccard overlap
 * (|intersection| / |union|) over those token sets. That is why it can be
 * ported at all — there is nothing to embed.
 *
 * IT MUST NEVER INDEX SECRET MATERIAL. The records file is plaintext on disk,
 * so anything indexed is readable by whatever can read the profile directory
 * — a backup, a sync client, another user on a shared machine — without the
 * master password. Python used to append a key_value entry's `value` here,
 * which put the stored secret in that file in the clear along with a
 * tokenized copy that leaked it just as well; that is fixed there and was
 * never done here. The rule is simple and worth keeping simple: nobody
 * searches for a secret they do not already know, so indexing one is pure
 * downside.
 */

const WORD_RE = /[a-z0-9_]+/g;

export const SEMANTIC_SCHEMA_VERSION = 1;
/** Bumped when secret values stopped being indexed; a v1 index still holds them. */
export const SEMANTIC_MODEL_ID = "seedpass-token-overlap-v2";

/** Kinds worth indexing. Others carry nothing searchable that is not secret. */
export const SEMANTIC_KINDS = new Set([
  "document",
  "note",
  "key_value",
  "password",
  "stored_password",
  "totp",
  "nostr",
  "ssh",
  "pgp",
]);

export interface SemanticRecord {
  entry_id: number;
  kind: string;
  label: string;
  text: string;
  /** Sorted, for a stable on-disk form. */
  tokens: string[];
}

export interface SemanticHit {
  entry_id: number;
  kind: string;
  label: string;
  score: number;
  excerpt: string;
}

export interface SemanticStatus {
  enabled: boolean;
  built: boolean;
  records: number;
  schema_version: number;
  model_id: string;
  updated_at: number;
}

export function tokenize(text: string): Set<string> {
  const lowered = text.trim().toLowerCase();
  if (!lowered) return new Set();
  return new Set(lowered.match(WORD_RE) ?? []);
}

/**
 * The searchable text for an entry.
 *
 * Every field here is a NAME or a note, never a value. Adding a field to this
 * function puts it in a plaintext file, so the question to ask of any
 * addition is not "would this be useful to search" but "would I be content
 * for it to sit unencrypted next to the vault".
 */
export function semanticText(entry: Record<string, unknown>, kind: string): string {
  const str = (v: unknown): string => String(v ?? "").trim();
  const parts: string[] = [str(entry["label"]), str(entry["notes"])];

  const tags = entry["tags"];
  parts.push(
    Array.isArray(tags) ? tags.map((t) => str(t)).filter(Boolean).join(" ") : str(tags),
  );

  if (kind === "document" || kind === "note") {
    parts.push(str(entry["content"]), str(entry["file_type"]));
  } else if (kind === "password" || kind === "stored_password") {
    // Username and URL, never the derived password.
    parts.push(str(entry["username"]), str(entry["url"]));
  } else if (kind === "key_value") {
    // The key NAME only. `value` is the secret; see the file header.
    parts.push(str(entry["key"]));
  } else if (kind === "totp") {
    parts.push(str(entry["issuer"]));
  } else if (kind === "nostr") {
    // The public half only.
    parts.push(str(entry["npub"]));
  } else if (kind === "ssh" || kind === "pgp") {
    parts.push(str(entry["fingerprint"]));
  }

  const links = entry["links"];
  if (Array.isArray(links)) {
    for (const link of links) {
      if (typeof link !== "object" || link === null) continue;
      const l = link as Record<string, unknown>;
      parts.push(str(l["relation"]), str(l["note"]));
    }
  }

  return parts.filter((p) => p).join("\n");
}

/** Build records from entries, skipping kinds and entries with nothing to index. */
export function buildSemanticRecords(
  entries: Array<Record<string, unknown>>,
): SemanticRecord[] {
  const records: SemanticRecord[] = [];
  for (const entry of entries) {
    // Entry 0 is a real entry — it is the FIRST one any profile creates — so
    // it cannot double as "missing". Both implementations used to test
    // `id <= 0`, which silently dropped it along with genuinely absent ids
    // and left every user's first entry permanently unfindable, with nothing
    // to indicate why. Fixed in both; see test/semanticIndex.test.ts.
    const rawId = entry["id"];
    if (rawId === undefined || rawId === null) continue;
    const entryId = Number(rawId);
    if (!Number.isInteger(entryId) || entryId < 0) continue;
    const kind = String(entry["kind"] ?? entry["type"] ?? "").trim().toLowerCase();
    if (!SEMANTIC_KINDS.has(kind)) continue;
    const text = semanticText(entry, kind);
    const tokens = tokenize(text);
    if (!text.trim() || tokens.size === 0) continue;
    records.push({
      entry_id: entryId,
      kind,
      label: String(entry["label"] ?? ""),
      text,
      tokens: [...tokens].sort(),
    });
  }
  return records;
}

/**
 * Score a query against built records.
 *
 * Jaccard overlap, ties broken by entry id so the order is stable and matches
 * Python's. Scores are rounded to six places for the same reason.
 */
export function searchSemanticRecords(
  records: SemanticRecord[],
  query: string,
  options: { k?: number; kind?: string | null } = {},
): SemanticHit[] {
  if (records.length === 0) return [];
  const queryTokens = tokenize(query);
  if (queryTokens.size === 0) return [];
  const wantedKind = options.kind ? options.kind.trim().toLowerCase() : null;

  const scored: Array<{ score: number; record: SemanticRecord }> = [];
  for (const record of records) {
    const recordKind = String(record.kind ?? "").trim().toLowerCase();
    if (wantedKind && recordKind !== wantedKind) continue;
    const tokens = new Set(
      record.tokens.map((t) => String(t).trim().toLowerCase()).filter((t) => t),
    );
    if (tokens.size === 0) continue;
    let intersection = 0;
    for (const token of queryTokens) if (tokens.has(token)) intersection++;
    if (intersection <= 0) continue;
    const union = new Set([...queryTokens, ...tokens]).size;
    scored.push({ score: intersection / (union || 1), record });
  }

  scored.sort((a, b) => b.score - a.score || a.record.entry_id - b.record.entry_id);
  const limit = Math.max(1, Math.trunc(options.k ?? 10));
  return scored.slice(0, limit).map(({ score, record }) => ({
    entry_id: record.entry_id,
    kind: record.kind,
    label: record.label,
    // Six decimal places, as Python rounds it.
    score: Math.round(score * 1e6) / 1e6,
    excerpt: record.text.slice(0, 220),
  }));
}

/** The manifest written beside the records. */
export function semanticManifest(options: {
  enabled: boolean;
  built: boolean;
  recordCount: number;
  updatedAt: number;
}): Record<string, unknown> {
  return {
    enabled: options.enabled,
    built: options.built,
    schema_version: SEMANTIC_SCHEMA_VERSION,
    model_id: SEMANTIC_MODEL_ID,
    updated_at: options.updatedAt,
    record_count: options.recordCount,
  };
}

export function semanticStatus(
  manifest: Record<string, unknown>,
  recordCount: number,
): SemanticStatus {
  return {
    enabled: Boolean(manifest["enabled"] ?? false),
    built: Boolean(manifest["built"] ?? false),
    records: recordCount,
    schema_version: Number(manifest["schema_version"] ?? SEMANTIC_SCHEMA_VERSION),
    model_id: String(manifest["model_id"] ?? SEMANTIC_MODEL_ID),
    updated_at: Number(manifest["updated_at"] ?? 0),
  };
}

/**
 * Is an index on disk one that was written before secrets stopped being
 * indexed?
 *
 * Such a file holds stored secrets in the clear, and fixing the writer does
 * not rewrite files already written — so anything that opens an index has to
 * check, and callers delete rather than read. Expecting a user to notice a
 * version string in a status field is not a remedy.
 *
 * A missing or unreadable manifest is NOT stale: there is nothing to purge,
 * and treating "cannot tell" as "delete it" would throw away a good index.
 */
export function isStaleSemanticIndex(manifest: Record<string, unknown>): boolean {
  const modelId = manifest["model_id"];
  if (modelId === undefined || modelId === null) return false;
  return String(modelId) !== SEMANTIC_MODEL_ID;
}
