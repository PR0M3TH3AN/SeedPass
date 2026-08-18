/**
 * Deterministic index merge with tombstones.
 *
 * Parity target: src/seedpass/core/sync_conflict.py (strategy
 * "modified_ts_hash_tombstone_v2"). Every rule here — timestamp precedence,
 * canonical-hash tie-breaks, field-level union at equal timestamps, tombstone
 * preference and retention — must match Python exactly; cross-client state
 * convergence depends on both implementations agreeing.
 *
 * The _system.index0 block is normalized only for the empty case; merging
 * populated index0 event logs is atlas-milestone work. Rather than silently
 * mis-merging, mergeIndexPayloads throws on non-empty index0 content.
 */

import { canonicalHash, canonicalJson } from "./canonical.js";

export const TOMBSTONE_RETENTION_CAP = 2048;
export const MERGE_STRATEGY = "modified_ts_hash_tombstone_v2";

type Dict = Record<string, unknown>;

function isDict(v: unknown): v is Dict {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Python int(raw) with a default on failure: truncates floats, accepts bools
 * and integer strings (with surrounding whitespace), rejects the rest. */
export function safeInt(raw: unknown, dflt = 0): number {
  if (typeof raw === "boolean") return raw ? 1 : 0;
  if (typeof raw === "number") {
    if (!Number.isFinite(raw)) return Math.trunc(dflt);
    return Math.trunc(raw);
  }
  if (typeof raw === "string") {
    const s = raw.trim();
    if (/^[+-]?\d+$/.test(s)) return parseInt(s, 10);
    return Math.trunc(dflt);
  }
  return Math.trunc(dflt);
}

function entryTs(entry: Dict): number {
  return safeInt(entry["modified_ts"] ?? 0, 0);
}

function isEmpty(value: unknown): boolean {
  if (value === null || value === undefined) return true;
  if (typeof value === "string") return value.trim() === "";
  return false;
}

function entryKind(entry: Dict): string {
  const raw = entry["kind"] ?? entry["type"] ?? "password";
  return String(raw).trim().toLowerCase();
}

/**
 * Python truthiness, which differs from JS on containers: bool([]) and
 * bool({}) are False in Python but Boolean([]) is true in JS. A
 * `"_deleted": []` field would tombstone an entry in JS and keep it in
 * Python — the two clients would then disagree about whether it exists.
 */
function pyTruthy(value: unknown): boolean {
  if (value === null || value === undefined) return false;
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === "object") return Object.keys(value as Dict).length > 0;
  return Boolean(value);
}

function isDeletedEntry(entry: Dict): boolean {
  return pyTruthy(entry["_deleted"]) || pyTruthy(entry["deleted"]);
}

function entryHash(entry: Dict): string {
  return canonicalHash(entry);
}

function entryEventHash(entry: Dict): string {
  return canonicalHash({ entry, kind: "entry" });
}

function tombstoneEventHash(record: Dict, idx: string): string {
  const provided = String(record["event_hash"] ?? "").trim().toLowerCase();
  if (provided) return provided;
  return canonicalHash({
    kind: "tombstone",
    index: String(idx),
    deleted_ts: safeInt(record["deleted_ts"] ?? 0, 0),
    entry_hash: String(record["entry_hash"] ?? ""),
  });
}

function preferTombstone(current: Dict, incoming: Dict, idx: string): boolean {
  const curTs = safeInt(current["deleted_ts"] ?? 0, 0);
  const incTs = safeInt(incoming["deleted_ts"] ?? 0, 0);
  if (incTs !== curTs) return incTs > curTs;
  return tombstoneEventHash(incoming, idx) > tombstoneEventHash(current, idx);
}

function normalizeTombstones(value: unknown): Record<string, Dict> {
  // Object.create(null): "__proto__" must behave as an ordinary key. On a
  // normal object it silently replaces the prototype instead of being
  // stored, which drops the record here and diverges from Python.
  const out: Record<string, Dict> = Object.create(null);
  if (!isDict(value)) return out;
  for (const [k, v] of Object.entries(value)) {
    if (!isDict(v)) continue;
    const deletedTs = safeInt(v["deleted_ts"] ?? 0, 0);
    if (deletedTs <= 0) continue;
    out[String(k)] = {
      deleted_ts: deletedTs,
      entry_hash: String(v["entry_hash"] ?? ""),
      event_hash: String(v["event_hash"] ?? ""),
      source: String(v["source"] ?? ""),
    };
  }
  return out;
}

function mergeTombstones(
  current: Record<string, Dict>,
  incoming: Record<string, Dict>,
): Record<string, Dict> {
  const merged: Record<string, Dict> = Object.assign(Object.create(null), current);
  for (const [idx, rec] of Object.entries(incoming)) {
    const cur = merged[idx];
    if (cur === undefined || preferTombstone(cur, rec, idx)) {
      merged[idx] = { ...rec };
    }
  }
  return merged;
}

function maxEntryTs(entries: Dict): number {
  let max = 0;
  for (const value of Object.values(entries)) {
    if (isDict(value)) {
      const ts = entryTs(value);
      if (ts > max) max = ts;
    }
  }
  return max;
}

/** Highest numeric key in a record, or -1 when none. Non-numeric keys are skipped. */
function maxNumericKey(record: Dict): number {
  let max = -1;
  for (const key of Object.keys(record)) {
    if (!/^(0|[1-9][0-9]*)$/.test(key)) continue;
    const id = Number(key);
    if (Number.isSafeInteger(id) && id > max) max = id;
  }
  return max;
}

function maxTombstoneTs(tombstones: Record<string, Dict>): number {
  let max = 0;
  for (const record of Object.values(tombstones)) {
    const ts = safeInt(record["deleted_ts"] ?? 0, 0);
    if (ts > max) max = ts;
  }
  return max;
}

/** True when incoming should replace current (higher ts, then larger hash). */
function preferEntry(current: Dict, incoming: Dict): boolean {
  const curTs = entryTs(current);
  const incTs = entryTs(incoming);
  if (incTs !== curTs) return incTs > curTs;
  return entryHash(incoming) > entryHash(current);
}

const UNION_FIELD_MATRIX: Record<string, string[]> = {
  password: ["username", "url"],
  totp: ["issuer"],
  key_value: ["key", "value"],
  managed_account: ["value", "user_id"],
  ssh: ["username", "public_key", "algorithm", "key_type"],
  pgp: ["public_key", "key_type"],
  nostr: ["npub", "public_key"],
  seed: ["path", "network", "coin_type"],
  document: ["content", "file_type"],
};
const COMMON_UNION_FIELDS = ["notes", "tags", "custom_fields", "links"];
const LIST_UNION_FIELDS = new Set(["tags", "custom_fields", "links"]);

function unionFieldsForKind(kind: string): string[] {
  return [...(UNION_FIELD_MATRIX[kind] ?? []), ...COMMON_UNION_FIELDS];
}

function mergeListUnion(preferred: unknown, other: unknown): unknown {
  if (Array.isArray(preferred) && Array.isArray(other)) {
    // Python dedupes by canonical JSON and returns items sorted by that key
    const byCanonical = new Map<string, unknown>();
    for (const item of [...preferred, ...other]) {
      byCanonical.set(canonicalJson(item ?? null), item);
    }
    return [...byCanonical.keys()].sort().map((k) => byCanonical.get(k));
  }
  return preferred;
}

/** Merge two entries carrying the same timestamp with field-level rules. */
function mergeEqualTsEntries(preferred: Dict, other: Dict, ts: number): Dict {
  const merged: Dict = { ...preferred };
  for (const field of unionFieldsForKind(entryKind(merged))) {
    const pv = merged[field];
    const ov = other[field];
    if (LIST_UNION_FIELDS.has(field)) {
      // Python assigns unconditionally; an absent value becomes JSON null
      const result = mergeListUnion(pv, ov);
      merged[field] = result === undefined ? null : result;
      continue;
    }
    if (isEmpty(pv) && !isEmpty(ov)) {
      merged[field] = ov;
    }
  }
  if ("archived" in preferred || "archived" in other) {
    merged["archived"] =
      Boolean(preferred["archived"] ?? false) || Boolean(other["archived"] ?? false);
  }
  merged["modified_ts"] = Math.trunc(ts);
  return merged;
}

/** Empty normalized index0 block (index0.py normalize_index0 on no content). */
export function emptyIndex0(): Dict {
  return {
    schema_version: 1,
    events: {},
    checkpoints: {},
    canonical_views: {},
    view_manifest: {
      version: 1,
      canonical_view_types: [],
      local_only_view_types: [],
      builder_versions: {},
    },
    heads: {},
    stats: {
      event_count: 0,
      checkpoint_count: 0,
      writer_count: 0,
      last_compaction_ts: 0,
      last_validation_ts: 0,
    },
  };
}

function assertIndex0Portable(raw: unknown): void {
  if (!isDict(raw)) return;
  for (const key of ["events", "checkpoints", "canonical_views"]) {
    const section = raw[key];
    if (isDict(section) && Object.keys(section).length > 0) {
      throw new Error(
        `_system.index0.${key} contains data; index0 content merge is not ` +
          `ported yet — refusing to merge rather than dropping it silently`,
      );
    }
  }
}

function ensureIndex0Payload(data: unknown, options: MergeOptions = {}): Dict {
  const out: Dict = isDict(data) ? { ...data } : {};
  const system: Dict = isDict(out["_system"]) ? { ...(out["_system"] as Dict) } : {};
  if (options.index0 !== "preserve-current") {
    assertIndex0Portable(system["index0"]);
    system["index0"] = emptyIndex0();
  }
  out["_system"] = system;
  return out;
}

export interface MergeOptions {
  /**
   * What to do with `_system.index0`, Python's derived atlas state.
   *
   * Default ("reject") refuses to merge populated index0 rather than drop
   * it silently. "preserve-current" keeps the current side's block verbatim
   * and ignores the incoming one — correct when merging remote state into a
   * live profile, since Python recomputes canonical views from entries on
   * load and would otherwise be blocked entirely.
   */
  index0?: "reject" | "preserve-current";
}

/** Deterministically merge two decrypted index payloads (Python parity). */
export function mergeIndexPayloads(
  currentRaw: unknown,
  incomingRaw: unknown,
  sourceTag = "",
  options: MergeOptions = {},
): Dict {
  const out = ensureIndex0Payload(
    isDict(currentRaw) ? structuredClone(currentRaw) : {},
    options,
  );
  const incoming = ensureIndex0Payload(
    isDict(incomingRaw) ? structuredClone(incomingRaw) : {},
    options,
  );

  // Rebuild entries on a null prototype for the same reason: an incoming
  // entry keyed "__proto__" would otherwise be dropped and pollute the
  // object's prototype chain.
  const curEntries: Dict = Object.assign(
    Object.create(null) as Dict,
    isDict(out["entries"]) ? (out["entries"] as Dict) : {},
  );
  const incEntries: Dict = isDict(incoming["entries"]) ? (incoming["entries"] as Dict) : {};
  const curMeta: Dict = isDict(out["_sync_meta"]) ? (out["_sync_meta"] as Dict) : {};
  const incMeta: Dict = isDict(incoming["_sync_meta"]) ? (incoming["_sync_meta"] as Dict) : {};

  let tombstones = mergeTombstones(
    normalizeTombstones(curMeta["tombstones"] ?? {}),
    normalizeTombstones(incMeta["tombstones"] ?? {}),
  );

  for (const [idx, incEntryRaw] of Object.entries(incEntries)) {
    if (!isDict(incEntryRaw)) continue;
    const key = String(idx);
    const incEntry = incEntryRaw;
    if (isDeletedEntry(incEntry)) {
      let deleteTs = entryTs(incEntry);
      if (deleteTs <= 0) {
        deleteTs = Math.max(
          safeInt(curMeta["last_merge_ts"] ?? 0, 0),
          safeInt(incMeta["last_merge_ts"] ?? 0, 0),
          maxEntryTs(curEntries),
          maxEntryTs(incEntries),
          maxTombstoneTs(tombstones),
        );
        if (deleteTs <= 0) deleteTs = 1;
      }
      tombstones = mergeTombstones(tombstones, {
        [key]: {
          deleted_ts: deleteTs,
          entry_hash: String(incEntry["entry_hash"] ?? ""),
          event_hash: entryEventHash(incEntry),
          source: sourceTag,
        },
      });
      delete curEntries[key];
      continue;
    }
    const curEntry = curEntries[key];
    if (!isDict(curEntry)) {
      curEntries[key] = incEntry;
      continue;
    }
    const curTs = entryTs(curEntry);
    const incTs = entryTs(incEntry);
    if (curTs === incTs) {
      if (preferEntry(curEntry, incEntry)) {
        curEntries[key] = mergeEqualTsEntries(incEntry, curEntry, incTs);
      } else {
        curEntries[key] = mergeEqualTsEntries(curEntry, incEntry, curTs);
      }
      continue;
    }
    if (preferEntry(curEntry, incEntry)) {
      curEntries[key] = incEntry;
    }
  }

  // Apply tombstones after the entry merge
  for (const [idx, rec] of Object.entries<Dict>(
    Object.assign(Object.create(null) as Record<string, Dict>, tombstones),
  )) {
    const entry = curEntries[idx];
    if (!isDict(entry)) continue;
    const eTs = entryTs(entry);
    const dTs = safeInt(rec["deleted_ts"] ?? 0, 0);
    if (eTs > dTs) {
      delete tombstones[idx];
      continue;
    }
    if (eTs < dTs) {
      delete curEntries[idx];
      continue;
    }
    if (tombstoneEventHash(rec, idx) > entryEventHash(entry)) {
      delete curEntries[idx];
    } else {
      delete tombstones[idx];
    }
  }

  out["entries"] = curEntries;
  if ("schema_version" in incoming) {
    out["schema_version"] = Math.max(
      safeInt(out["schema_version"] ?? 0, 0),
      safeInt(incoming["schema_version"] ?? 0, 0),
    );
  }

  const meta: Dict = isDict(out["_sync_meta"]) ? (out["_sync_meta"] as Dict) : {};
  let sources: string[] = Array.isArray(meta["sources"])
    ? (meta["sources"] as unknown[]).map((v) => String(v)).filter((v) => v)
    : [];
  if (sourceTag && !sources.includes(sourceTag)) sources.push(sourceTag);
  sources = [...new Set(sources)].sort();

  if (Object.keys(tombstones).length > 0) {
    let items = Object.entries(tombstones).sort((a, b) => {
      const ta = safeInt(a[1]["deleted_ts"] ?? 0, 0);
      const tb = safeInt(b[1]["deleted_ts"] ?? 0, 0);
      if (ta !== tb) return ta - tb;
      return a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0;
    });
    if (items.length > TOMBSTONE_RETENTION_CAP) {
      items = items.slice(-TOMBSTONE_RETENTION_CAP);
    }
    tombstones = Object.fromEntries(items);
  }

  const lastMergeTs = Math.max(
    safeInt(meta["last_merge_ts"] ?? 0, 0),
    safeInt(incMeta["last_merge_ts"] ?? 0, 0),
    maxEntryTs(curEntries),
    maxTombstoneTs(tombstones),
  );

  // Allocation watermark: never below either side's watermark, nor below one
  // past any merged entry or tombstone id. Without this, merging a deletion
  // lets max(live)+1 reissue the deleted id — and an entry id is a permanent
  // BIP-85 derivation coordinate, so reissuing #184 hands a NEW entry the
  // departed identity's exact derived secrets. Must stay byte-identical to
  // the Python computation in sync_conflict.py.
  const nextIndexWatermark = Math.max(
    safeInt(meta["next_index"] ?? 0, 0),
    safeInt(incMeta["next_index"] ?? 0, 0),
    maxNumericKey(curEntries) + 1,
    maxNumericKey(tombstones) + 1,
    0,
  );

  Object.assign(meta, {
    strategy: MERGE_STRATEGY,
    last_merge_ts: lastMergeTs,
    next_index: nextIndexWatermark,
    source_count: sources.length,
    sources: sources.slice(-32),
    tombstones,
  });
  out["_sync_meta"] = meta;

  const outSystem: Dict = isDict(out["_system"]) ? (out["_system"] as Dict) : {};
  if (options.index0 !== "preserve-current") {
    outSystem["index0"] = emptyIndex0();
  }
  out["_system"] = outSystem;
  return out;
}
