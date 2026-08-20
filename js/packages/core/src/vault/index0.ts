/**
 * index0 / atlas — parity with src/seedpass/core/index0.py.
 *
 * A per-vault activity ledger that lives inside the encrypted index under
 * `_system.index0`. It holds an append-only stream of events per writer,
 * daily checkpoints rolling those events up, and derived "canonical views"
 * (children, counts by kind, recent activity) that other tooling reads
 * instead of walking the whole vault.
 *
 * Everything here is DERIVED state: it can be rebuilt from the entries and
 * the event stream. That is why the port could safely carry it verbatim
 * before now — but carrying it verbatim meant a TypeScript client never
 * updated it, so a vault written by this port went stale the moment it was
 * touched, and a Python client reading it afterwards saw an activity log
 * missing everything the TS client had done.
 *
 * HASH PARITY IS THE WHOLE CONTRACT. Event ids, integrity hashes, checkpoint
 * summaries and view hashes are all SHA-256 over Python's canonical JSON, and
 * the merge picks winners by comparing those hashes. A single byte of
 * disagreement in the encoding means the two implementations disagree about
 * which record wins, permanently. Everything routes through `canonicalJson`
 * (which already handles Python's ensure_ascii escaping, code-point key
 * ordering and number formatting) rather than JSON.stringify.
 */

import { canonicalJson, canonicalHash, compareCodePoints } from "../sync/canonical.js";

export const INDEX0_SCHEMA_VERSION = 1;
export const INDEX0_CHECKPOINT_SUBJECT_CAP = 64;
export const INDEX0_MAX_CHECKPOINTS_PER_WRITER = 30;
export const INDEX0_MANIFEST_CHECKPOINT_LIMIT = 32;
export const INDEX0_RECENT_ACTIVITY_LIMIT = 20;

/** Views that never leave the machine that built them. */
export const LOCAL_ONLY_VIEW_TYPES = ["conversation_index", "hot_nodes", "semantic_neighbors"];
export const INDEX0_CANONICAL_VIEW_TYPES = [
  "children_of",
  "counts_by_kind",
  "recent_activity",
] as const;

export type Dict = Record<string, unknown>;

export interface Index0 {
  schema_version: number;
  events: Record<string, Dict>;
  checkpoints: Record<string, Dict>;
  canonical_views: Record<string, Dict>;
  view_manifest: Dict;
  heads: Record<string, Dict>;
  stats: Dict;
}

function isDict(value: unknown): value is Dict {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Python's `str(value)`, which is not JavaScript's `String(value)`.
 *
 * `str(None)` is "None", `str(True)` is "True". Those are quirks rather than
 * intentions, but they decide whether a required field counts as present, so
 * a vault Python accepted must be accepted here too — and hash identically.
 * Diverging would mean the two implementations disagree about which events
 * exist, which is worse than agreeing on an odd answer.
 */
function pythonStr(value: unknown): string {
  if (value === null || value === undefined) return "None";
  if (value === true) return "True";
  if (value === false) return "False";
  return String(value);
}

function normalizeString(value: unknown): string {
  return pythonStr(value).trim();
}

/**
 * Python's `int(raw)` with a fallback.
 *
 * Accepts integers, truncates floats toward zero, and parses decimal strings
 * with optional sign, surrounding whitespace and PEP 515 underscores. Anything
 * else (including "3.9", "0x10" and NaN) falls back, exactly as the
 * `except Exception` in Python does.
 */
function safeInt(raw: unknown, fallback = 0): number {
  if (typeof raw === "number") {
    if (!Number.isFinite(raw)) return fallback;
    return Math.trunc(raw);
  }
  if (typeof raw === "boolean") return raw ? 1 : 0;
  if (typeof raw === "string") {
    const text = raw.trim().replace(/_/g, "");
    if (!/^[+-]?\d+$/.test(text)) return fallback;
    const parsed = Number(text);
    return Number.isFinite(parsed) ? parsed : fallback;
  }
  return fallback;
}

function normalizeMapping(raw: unknown): Dict {
  return isDict(raw) ? { ...raw } : {};
}

/** Deduplicated, code-point sorted, blanks dropped — Python's sorted(set(...)). */
function normalizeTags(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  const seen = new Set<string>();
  for (const tag of raw) {
    const value = normalizeString(tag);
    if (value) seen.add(value);
  }
  return [...seen].sort(compareCodePoints);
}

function normalizeLinks(raw: unknown): Dict[] {
  if (!Array.isArray(raw)) return [];
  // Keyed by canonical form so duplicates collapse, then emitted in key
  // order — the same dict-keyed dedupe Python does.
  const byKey = new Map<string, Dict>();
  for (const item of raw) {
    if (!isDict(item)) continue;
    const targetId = normalizeString(item["target_id"] ?? "");
    const relation = normalizeString(item["relation"] ?? "");
    const note = normalizeString(item["note"] ?? "");
    if (!targetId || !relation) continue;
    const normalized: Dict = { target_id: targetId, relation };
    if (note) normalized["note"] = note;
    byKey.set(canonicalJson(normalized), normalized);
  }
  return [...byKey.keys()].sort(compareCodePoints).map((key) => byKey.get(key)!);
}

// ------------------------------------------------------------------ hashes

/** Hash of an event, excluding its own integrity hash. */
export function computeEventHash(event: Dict): string {
  const body = { ...event };
  delete body["integrity_hash"];
  return canonicalHash(body);
}

export function computeEventId(event: Dict): string {
  return `e:${computeEventHash(event)}`;
}

/** The per-writer head marker: what the next event chains onto. */
export function computeHeadHash(event: Dict): string {
  return canonicalHash({
    event_id: normalizeString(event["event_id"] ?? ""),
    integrity_hash: normalizeString(event["integrity_hash"] ?? ""),
    prev_hash: normalizeString(event["prev_hash"] ?? ""),
    writer_id: normalizeString(event["writer_id"] ?? ""),
  });
}

export function computeCheckpointHash(checkpoint: Dict): string {
  const body = { ...checkpoint };
  delete body["summary_hash"];
  return canonicalHash(body);
}

export function computeViewHash(view: Dict): string {
  const body = { ...view };
  delete body["view_hash"];
  return canonicalHash(body);
}

/** UTC calendar day, the checkpoint window key. */
function windowKeyForTs(ts: number): string {
  return new Date(safeInt(ts) * 1000).toISOString().slice(0, 10);
}

function eventSortKey(event: Dict): [number, string] {
  return [safeInt(event["modified_ts"] ?? 0), normalizeString(event["event_id"] ?? "")];
}

function compareEvents(a: Dict, b: Dict): number {
  const [ats, aid] = eventSortKey(a);
  const [bts, bid] = eventSortKey(b);
  return ats - bts || compareCodePoints(aid, bid);
}

// ------------------------------------------------------------- normalizers

export function normalizeIndex0Event(raw: unknown): Dict | null {
  if (!isDict(raw)) return null;
  const modifiedTs = safeInt(raw["modified_ts"] ?? 0);
  // A timestamp is what orders the stream; an event without one cannot be
  // placed, so it is dropped rather than guessed at.
  if (modifiedTs <= 0) return null;

  const event: Dict = {
    event_type: normalizeString(raw["event_type"] ?? ""),
    subject_type: normalizeString(raw["subject_type"] ?? ""),
    subject_id: normalizeString(raw["subject_id"] ?? ""),
    subject_kind: normalizeString(raw["subject_kind"] ?? ""),
    scope_path: normalizeString(raw["scope_path"] ?? ""),
    actor_type: normalizeString(raw["actor_type"] ?? ""),
    actor_id: normalizeString(raw["actor_id"] ?? ""),
    writer_id: normalizeString(raw["writer_id"] ?? ""),
    modified_ts: modifiedTs,
    prev_hash: normalizeString(raw["prev_hash"] ?? ""),
    classification: normalizeString(raw["classification"] ?? "internal") || "internal",
    partition: normalizeString(raw["partition"] ?? "standard") || "standard",
    payload_ref: normalizeMapping(raw["payload_ref"]),
    links: normalizeLinks(raw["links"]),
    tags: normalizeTags(raw["tags"]),
    visibility: normalizeString(raw["visibility"] ?? "private") || "private",
  };
  // Optional fields are present only when non-empty, because their presence
  // changes the hash.
  for (const key of ["policy_ref", "source", "source_event_id", "summary"]) {
    const value = normalizeString(raw[key] ?? "");
    if (value) event[key] = value;
  }
  if (
    !event["event_type"] ||
    !event["subject_type"] ||
    !event["subject_id"] ||
    !event["writer_id"]
  ) {
    return null;
  }

  event["integrity_hash"] = normalizeString(raw["integrity_hash"] ?? "");
  const expected = computeEventHash(event);
  // A stored hash is preserved even when it disagrees: this normalizes, it
  // does not verify, and silently rewriting a mismatched hash would hide
  // exactly the tampering the hash exists to reveal.
  if (!event["integrity_hash"]) event["integrity_hash"] = expected;
  event["event_id"] = normalizeString(raw["event_id"] ?? "") || `e:${expected}`;
  return event;
}

export function normalizeIndex0Checkpoint(raw: unknown): Dict | null {
  if (!isDict(raw)) return null;
  const checkpointId = normalizeString(raw["checkpoint_id"] ?? "");
  const writerId = normalizeString(raw["writer_id"] ?? "");
  const windowType = normalizeString(raw["window_type"] ?? "");
  const windowKey = normalizeString(raw["window_key"] ?? "");
  const modifiedTs = safeInt(raw["modified_ts"] ?? 0);
  if (!checkpointId || !writerId || !windowType || !windowKey || modifiedTs <= 0) {
    return null;
  }

  const rollup = normalizeMapping(raw["rollup"]);
  const countMap = (source: unknown): Dict => {
    const out: Dict = {};
    for (const key of Object.keys(normalizeMapping(source)).sort(compareCodePoints)) {
      const name = normalizeString(key);
      if (name) out[name] = safeInt(normalizeMapping(source)[key] ?? 0);
    }
    return out;
  };

  const checkpoint: Dict = {
    checkpoint_id: checkpointId,
    window_type: windowType,
    window_key: windowKey,
    writer_id: writerId,
    window_start_ts: safeInt(raw["window_start_ts"] ?? 0),
    window_end_ts: safeInt(raw["window_end_ts"] ?? 0),
    event_count: Math.max(0, safeInt(raw["event_count"] ?? 0)),
    head_hash: normalizeString(raw["head_hash"] ?? ""),
    rollup: {
      events_by_type: countMap(rollup["events_by_type"]),
      subjects_by_kind: countMap(rollup["subjects_by_kind"]),
      subjects: normalizeTags(rollup["subjects"]),
    },
    modified_ts: modifiedTs,
  };
  checkpoint["summary_hash"] =
    normalizeString(raw["summary_hash"] ?? "") || computeCheckpointHash(checkpoint);
  return checkpoint;
}

export function normalizeCanonicalView(
  raw: unknown,
  options: { viewManifest?: Dict | null } = {},
): Dict | null {
  if (!isDict(raw)) return null;
  const viewType = normalizeString(raw["view_type"] ?? "");
  const modifiedTs = safeInt(raw["modified_ts"] ?? 0);
  if (!viewType || modifiedTs <= 0) return null;
  // Local-only views must never be written into a shared vault: they are
  // derived from data that does not leave the machine, so syncing them would
  // publish inferences about it.
  if (LOCAL_ONLY_VIEW_TYPES.includes(viewType)) return null;
  const manifest = options.viewManifest;
  if (manifest) {
    const localOnly = manifest["local_only_view_types"];
    if (Array.isArray(localOnly) && localOnly.map(String).includes(viewType)) return null;
  }

  const view: Dict = {
    view_id: normalizeString(raw["view_id"] ?? ""),
    view_type: viewType,
    scope_path: normalizeString(raw["scope_path"] ?? ""),
    source_checkpoint_ids: normalizeTags(raw["source_checkpoint_ids"]),
    source_event_ids: normalizeTags(raw["source_event_ids"]),
    data: normalizeMapping(raw["data"]),
    modified_ts: modifiedTs,
  };
  if (!view["view_id"]) return null;
  view["view_hash"] = normalizeString(raw["view_hash"] ?? "") || computeViewHash(view);
  return view;
}

export function normalizeHead(raw: unknown): Dict | null {
  if (!isDict(raw)) return null;
  const eventId = normalizeString(raw["event_id"] ?? "");
  const headHash = normalizeString(raw["head_hash"] ?? "");
  const modifiedTs = safeInt(raw["modified_ts"] ?? 0);
  if (!eventId || !headHash || modifiedTs <= 0) return null;
  return { event_id: eventId, head_hash: headHash, modified_ts: modifiedTs };
}

export function normalizeViewManifest(raw: unknown): Dict {
  const data = normalizeMapping(raw);
  const stringSet = (value: unknown): string[] => {
    if (!Array.isArray(value)) return [];
    const seen = new Set<string>();
    for (const item of value) {
      const text = normalizeString(item);
      if (text) seen.add(text);
    }
    return [...seen].sort(compareCodePoints);
  };
  const builderVersions: Dict = {};
  const rawVersions = data["builder_versions"];
  if (isDict(rawVersions)) {
    for (const key of Object.keys(rawVersions).sort(compareCodePoints)) {
      const name = normalizeString(key);
      if (name) builderVersions[name] = safeInt(rawVersions[key] ?? 1, 1);
    }
  }
  return {
    version: Math.max(1, safeInt(data["version"] ?? 1, 1)),
    canonical_view_types: stringSet(data["canonical_view_types"]),
    local_only_view_types: stringSet(data["local_only_view_types"]),
    builder_versions: builderVersions,
  };
}

// Typed to exactly what it reads. It used to take a bare Dict, so every one
// of its five callers — all holding a real Index0 — had to launder it through
// `as unknown as Dict` to get in. A Pick says what the function needs, admits
// any Index0 without ceremony, and still accepts a partial one.
export function recomputeIndex0Stats(
  index0: Pick<Index0, "events" | "checkpoints" | "heads">,
): Dict {
  const events = normalizeMapping(index0["events"]);
  const checkpoints = normalizeMapping(index0["checkpoints"]);
  const heads = normalizeMapping(index0["heads"]);
  const timestamps = (source: Dict): number[] =>
    Object.values(source)
      .filter(isDict)
      .map((value) => safeInt(value["modified_ts"] ?? 0));
  const checkpointTs = timestamps(checkpoints);
  const headTs = timestamps(heads);
  return {
    event_count: Object.keys(events).length,
    checkpoint_count: Object.keys(checkpoints).length,
    writer_count: Object.keys(heads).length,
    last_compaction_ts: checkpointTs.length ? Math.max(...checkpointTs) : 0,
    last_validation_ts: headTs.length ? Math.max(...headTs) : 0,
  };
}

export function normalizeIndex0(raw: unknown): Index0 {
  const data = normalizeMapping(raw);
  const normalized: Index0 = {
    schema_version: Math.max(
      INDEX0_SCHEMA_VERSION,
      safeInt(data["schema_version"] ?? INDEX0_SCHEMA_VERSION, 1),
    ),
    events: {},
    checkpoints: {},
    canonical_views: {},
    view_manifest: {},
    heads: {},
    stats: {},
  };
  for (const [eventId, event] of Object.entries(normalizeMapping(data["events"]))) {
    const normalizedEvent = normalizeIndex0Event(event);
    if (normalizedEvent) normalized.events[String(eventId)] = normalizedEvent;
  }
  for (const [id, checkpoint] of Object.entries(normalizeMapping(data["checkpoints"]))) {
    const normalizedCheckpoint = normalizeIndex0Checkpoint(checkpoint);
    if (normalizedCheckpoint) normalized.checkpoints[String(id)] = normalizedCheckpoint;
  }
  const viewManifest = normalizeViewManifest(data["view_manifest"]);
  normalized.view_manifest = viewManifest;
  for (const [viewId, view] of Object.entries(normalizeMapping(data["canonical_views"]))) {
    const normalizedView = normalizeCanonicalView(view, { viewManifest });
    if (normalizedView) normalized.canonical_views[String(viewId)] = normalizedView;
  }
  for (const [writerId, head] of Object.entries(normalizeMapping(data["heads"]))) {
    const normalizedHead = normalizeHead(head);
    if (normalizedHead) normalized.heads[String(writerId)] = normalizedHead;
  }
  normalized.stats = recomputeIndex0Stats(normalized);
  return normalized;
}

// ------------------------------------------------------------------ context

export interface Index0Context {
  actor_type: string;
  actor_id: string;
  writer_id: string;
  scope_path: string;
  root_fingerprint: string;
  current_fingerprint: string;
}

/**
 * Who is writing, and where in the seed hierarchy.
 *
 * A managed account lives at `<root>/accounts/<child>`, and its scope path
 * names both so views from a child and its parent do not collide.
 */
export function deriveIndex0Context(
  fingerprintDir: string,
  options: { actorType?: string } = {},
): Index0Context {
  const parts = fingerprintDir.replace(/\/+$/, "").split("/");
  const currentFp = (parts[parts.length - 1] ?? "").trim();
  const parentName = parts[parts.length - 2] ?? "";
  let rootFp = currentFp;
  let scopePath = `seed/${currentFp}`;
  if (parentName === "accounts") {
    rootFp = (parts[parts.length - 3] ?? "").trim();
    scopePath = `seed/${rootFp}/managed/${currentFp}`;
  }
  return {
    actor_type: normalizeString(options.actorType ?? "user") || "user",
    actor_id: currentFp,
    writer_id: `writer:profile:${currentFp}`,
    scope_path: scopePath,
    root_fingerprint: rootFp,
    current_fingerprint: currentFp,
  };
}

/** Ensure `_system.index0` exists and is normalized, without touching entries. */
export function ensureIndex0Payload(data: unknown): Dict {
  const out = isDict(data) ? { ...data } : {};
  const system = isDict(out["_system"]) ? { ...(out["_system"] as Dict) } : {};
  system["index0"] = normalizeIndex0(system["index0"]);
  out["_system"] = system;
  return out;
}

// ------------------------------------------------------------------- events

export interface MakeEventOptions {
  eventType: string;
  subjectType: string;
  subjectId: unknown;
  subjectKind: string;
  modifiedTs: number;
  writerId: string;
  actorId: string;
  scopePath: string;
  actorType?: string;
  payloadRef?: Dict | null;
  links?: unknown[] | null;
  tags?: unknown[] | null;
  prevHash?: string;
  classification?: string;
  partition?: string;
  visibility?: string;
  policyRef?: string;
  source?: string;
  sourceEventId?: string;
  summary?: string;
}

export function makeIndex0Event(options: MakeEventOptions): Dict {
  const event: Dict = {
    event_type: normalizeString(options.eventType),
    subject_type: normalizeString(options.subjectType),
    subject_id: normalizeString(options.subjectId),
    subject_kind: normalizeString(options.subjectKind),
    scope_path: normalizeString(options.scopePath),
    actor_type: normalizeString(options.actorType ?? "user") || "user",
    actor_id: normalizeString(options.actorId),
    writer_id: normalizeString(options.writerId),
    // A zero or negative timestamp would make the event unorderable and
    // normalizeIndex0Event would then discard it, so it is floored at 1.
    modified_ts: Math.max(1, safeInt(options.modifiedTs, 1)),
    prev_hash: normalizeString(options.prevHash ?? ""),
    classification: normalizeString(options.classification ?? "internal") || "internal",
    partition: normalizeString(options.partition ?? "standard") || "standard",
    payload_ref: normalizeMapping(options.payloadRef),
    links: normalizeLinks(options.links),
    tags: normalizeTags(options.tags),
    visibility: normalizeString(options.visibility ?? "private") || "private",
  };
  for (const [key, value] of [
    ["policy_ref", options.policyRef],
    ["source", options.source],
    ["source_event_id", options.sourceEventId],
    ["summary", options.summary],
  ] as const) {
    const normalized = normalizeString(value ?? "");
    if (normalized) event[key] = normalized;
  }
  event["integrity_hash"] = computeEventHash(event);
  event["event_id"] = computeEventId(event);
  return normalizeIndex0Event(event) ?? event;
}

export interface AppendEventOptions extends Omit<
  MakeEventOptions,
  "writerId" | "actorId" | "scopePath" | "prevHash"
> {
  fingerprintDir: string;
}

/**
 * Append an event to the payload's stream and advance the writer's head.
 *
 * The event chains onto the writer's current head, so a gap or a rewrite is
 * detectable: `prev_hash` names what this writer last wrote.
 */
export function appendIndex0Event(payload: unknown, options: AppendEventOptions): Dict {
  const out = ensureIndex0Payload(payload);
  const system = (out["_system"] as Dict)["index0"] as unknown as Index0;
  const context = deriveIndex0Context(options.fingerprintDir, {
    ...(options.actorType !== undefined && { actorType: options.actorType }),
  });
  const head = system.heads[context.writer_id];
  const prevHash = isDict(head) ? normalizeString(head["head_hash"] ?? "") : "";

  const event = makeIndex0Event({
    ...options,
    writerId: context.writer_id,
    actorId: context.actor_id,
    scopePath: context.scope_path,
    actorType: context.actor_type,
    prevHash,
  });

  system.events[String(event["event_id"])] = event;
  system.heads[context.writer_id] = {
    event_id: event["event_id"] as string,
    head_hash: computeHeadHash(event),
    modified_ts: event["modified_ts"] as number,
  };
  system.stats = recomputeIndex0Stats(system);
  return out;
}

// -------------------------------------------------------------- checkpoints

export function buildDailyCheckpoint(
  writerId: string,
  windowKey: string,
  events: unknown[],
): Dict | null {
  const ordered = events
    .map((event) => normalizeIndex0Event(event))
    .filter((event): event is Dict => event !== null)
    .sort(compareEvents);
  if (ordered.length === 0) return null;

  const latest = ordered[ordered.length - 1]!;
  const eventsByType: Record<string, number> = {};
  const subjectsByKind: Record<string, number> = {};
  const subjectSet = new Set<string>();
  for (const event of ordered) {
    const subjectId = normalizeString(event["subject_id"] ?? "");
    if (subjectId) subjectSet.add(subjectId);
    const eventType = normalizeString(event["event_type"] ?? "");
    const subjectKind = normalizeString(event["subject_kind"] ?? "");
    if (eventType) eventsByType[eventType] = (eventsByType[eventType] ?? 0) + 1;
    if (subjectKind) subjectsByKind[subjectKind] = (subjectsByKind[subjectKind] ?? 0) + 1;
  }
  // Capped so one busy day cannot make a checkpoint unbounded.
  const subjects = [...subjectSet].sort(compareCodePoints).slice(0, INDEX0_CHECKPOINT_SUBJECT_CAP);

  const sortedCounts = (source: Record<string, number>): Dict => {
    const out: Dict = {};
    for (const key of Object.keys(source).sort(compareCodePoints)) out[key] = source[key]!;
    return out;
  };

  const checkpoint: Dict = {
    checkpoint_id: `cp:day:${windowKey}:${writerId}`,
    window_type: "day",
    window_key: windowKey,
    writer_id: writerId,
    window_start_ts: safeInt(ordered[0]!["modified_ts"] ?? 0),
    window_end_ts: safeInt(latest["modified_ts"] ?? 0),
    event_count: ordered.length,
    head_hash: computeHeadHash(latest),
    rollup: {
      events_by_type: sortedCounts(eventsByType),
      subjects_by_kind: sortedCounts(subjectsByKind),
      subjects,
    },
    modified_ts: safeInt(latest["modified_ts"] ?? 0),
  };
  checkpoint["summary_hash"] = computeCheckpointHash(checkpoint);
  return normalizeIndex0Checkpoint(checkpoint);
}

export function rebuildIndex0Checkpoints(
  index0: Dict,
  options: { maxCheckpointsPerWriter?: number } = {},
): Record<string, Dict> {
  const maxPerWriter = options.maxCheckpointsPerWriter ?? INDEX0_MAX_CHECKPOINTS_PER_WRITER;
  const grouped = new Map<string, Dict[]>();
  for (const event of Object.values(normalizeMapping(index0["events"]))) {
    const normalized = normalizeIndex0Event(event);
    if (!normalized) continue;
    const writerId = normalizeString(normalized["writer_id"] ?? "");
    if (!writerId) continue;
    const windowKey = windowKeyForTs(safeInt(normalized["modified_ts"] ?? 0));
    // The key joins on a character that cannot appear in a date, so a writer
    // id containing the separator cannot forge a different grouping.
    const key = `${windowKey} ${writerId}`;
    const bucket = grouped.get(key) ?? [];
    bucket.push(normalized);
    grouped.set(key, bucket);
  }

  const checkpoints: Record<string, Dict> = {};
  const windowsByWriter = new Map<string, Set<string>>();
  for (const [key, writerEvents] of grouped) {
    const [windowKey, writerId] = key.split(" ") as [string, string];
    const checkpoint = buildDailyCheckpoint(writerId, windowKey, writerEvents);
    if (!checkpoint) continue;
    checkpoints[String(checkpoint["checkpoint_id"])] = checkpoint;
    const windows = windowsByWriter.get(writerId) ?? new Set<string>();
    windows.add(windowKey);
    windowsByWriter.set(writerId, windows);
  }

  // Keep the most recent windows per writer, so history is bounded without
  // one noisy writer evicting another's checkpoints.
  const retained = new Set<string>();
  for (const [writerId, windows] of windowsByWriter) {
    const keep = [...windows].sort(compareCodePoints).reverse().slice(0, Math.max(1, maxPerWriter));
    for (const windowKey of keep) retained.add(`cp:day:${windowKey}:${writerId}`);
  }

  const out: Record<string, Dict> = {};
  for (const id of [...retained].sort(compareCodePoints)) {
    if (checkpoints[id]) out[id] = checkpoints[id]!;
  }
  return out;
}

export function compactIndex0(
  index0: unknown,
  options: { maxCheckpointsPerWriter?: number } = {},
): Index0 {
  const normalized = normalizeIndex0(index0);
  normalized.checkpoints = rebuildIndex0Checkpoints(
    normalized as unknown as Dict,
    options,
  );
  normalized.stats = recomputeIndex0Stats(normalized);
  return normalized;
}

// ------------------------------------------------------------------- views

function normalizeEntrySummary(entryId: string, entry: Dict): Dict {
  const kind = normalizeString(entry["kind"] ?? entry["type"] ?? "password") || "password";
  return {
    entry_id: normalizeString(entryId),
    kind,
    label: normalizeString(entry["label"] ?? entry["website"] ?? ""),
    archived: Boolean(entry["archived"] ?? entry["blacklisted"] ?? false),
    modified_ts: safeInt(entry["modified_ts"] ?? entry["updated"] ?? 0),
    link_count: normalizeLinks(entry["links"] ?? []).length,
    tag_count: normalizeTags(entry["tags"] ?? []).length,
  };
}

/**
 * Order entry ids numerically, tolerating ids that are not numbers.
 *
 * Entry ids are normally decimal strings, but an index that has been hand
 * edited, partially restored, or written by another tool can hold anything.
 * A malformed id must degrade the ordering, not break view building — for a
 * password manager, a vault that will not open is indistinguishable from one
 * that is lost.
 */
function compareEntryIds(a: string, b: string): number {
  const an = /^[+-]?\d+$/.test(a.trim()) ? Number(a.trim()) : null;
  const bn = /^[+-]?\d+$/.test(b.trim()) ? Number(b.trim()) : null;
  if (an !== null && bn !== null) return an - bn;
  if (an !== null) return -1;
  if (bn !== null) return 1;
  return compareCodePoints(a, b);
}

function buildChildrenView(
  scopePath: string,
  entries: Dict,
  eventIds: string[],
  checkpointIds: string[],
): Dict {
  const items = Object.keys(normalizeMapping(entries))
    .sort(compareEntryIds)
    .filter((id) => isDict(normalizeMapping(entries)[id]))
    .map((id) => normalizeEntrySummary(id, normalizeMapping(entries)[id] as Dict));
  const timestamps = items.map((item) => item["modified_ts"] as number).filter((ts) => ts > 0);
  return {
    view_id: `children_of:${scopePath}`,
    view_type: "children_of",
    scope_path: scopePath,
    source_checkpoint_ids: checkpointIds,
    source_event_ids: eventIds,
    data: { children: items, total_children: items.length },
    modified_ts: Math.max(1, timestamps.length ? Math.max(...timestamps) : 0),
  };
}

function buildCountsView(
  scopePath: string,
  entries: Dict,
  eventIds: string[],
  checkpointIds: string[],
): Dict {
  const counts: Record<string, number> = {};
  let archivedCount = 0;
  const timestamps: number[] = [];
  for (const entry of Object.values(normalizeMapping(entries))) {
    if (!isDict(entry)) continue;
    const kind = normalizeString(entry["kind"] ?? entry["type"] ?? "password");
    if (kind) counts[kind] = (counts[kind] ?? 0) + 1;
    if (entry["archived"] ?? entry["blacklisted"] ?? false) archivedCount++;
    timestamps.push(safeInt(entry["modified_ts"] ?? entry["updated"] ?? 0));
  }
  const sorted: Dict = {};
  for (const key of Object.keys(counts).sort(compareCodePoints)) sorted[key] = counts[key]!;
  return {
    view_id: `counts_by_kind:${scopePath}`,
    view_type: "counts_by_kind",
    scope_path: scopePath,
    source_checkpoint_ids: checkpointIds,
    source_event_ids: eventIds,
    data: {
      counts: sorted,
      archived_count: archivedCount,
      total_entries: Object.values(counts).reduce((a, b) => a + b, 0),
    },
    modified_ts: Math.max(1, timestamps.length ? Math.max(...timestamps) : 0),
  };
}

function buildRecentActivityView(
  scopePath: string,
  events: Dict[],
  checkpointIds: string[],
): Dict {
  const ordered = [...events].sort((a, b) => -compareEvents(a, b)).slice(
    0,
    INDEX0_RECENT_ACTIVITY_LIMIT,
  );
  const items = ordered.map((event) => ({
    event_id: normalizeString(event["event_id"] ?? ""),
    event_type: normalizeString(event["event_type"] ?? ""),
    subject_id: normalizeString(event["subject_id"] ?? ""),
    subject_kind: normalizeString(event["subject_kind"] ?? ""),
    modified_ts: safeInt(event["modified_ts"] ?? 0),
    summary: normalizeString(event["summary"] ?? ""),
  }));
  const timestamps = items.map((item) => item.modified_ts).filter((ts) => ts > 0);
  return {
    view_id: `recent_activity:${scopePath}`,
    view_type: "recent_activity",
    scope_path: scopePath,
    source_checkpoint_ids: checkpointIds,
    source_event_ids: items.map((item) => item.event_id).filter((id) => id),
    data: { items, total_items: items.length },
    modified_ts: Math.max(1, timestamps.length ? Math.max(...timestamps) : 0),
  };
}

/** Rebuild every canonical view from the entries and the event stream. */
export function rebuildCanonicalViewsPayload(
  payload: unknown,
  options: { fingerprintDir?: string | null } = {},
): Dict {
  const out = ensureIndex0Payload(payload);
  const index0 = (out["_system"] as Dict)["index0"] as unknown as Index0;
  const entries = normalizeMapping(out["entries"]);
  const events = Object.values(index0.events)
    .map((event) => normalizeIndex0Event(event))
    .filter((event): event is Dict => event !== null);
  const checkpoints = normalizeMapping(index0.checkpoints);

  const scopePaths = new Set<string>();
  for (const event of events) {
    const scope = normalizeString(event["scope_path"] ?? "");
    if (scope) scopePaths.add(scope);
  }
  if (options.fingerprintDir !== undefined && options.fingerprintDir !== null) {
    scopePaths.add(deriveIndex0Context(options.fingerprintDir).scope_path);
  }

  const views: Record<string, Dict> = {};
  for (const scopePath of [...scopePaths].filter((s) => s).sort(compareCodePoints)) {
    const scopeEvents = events.filter(
      (event) => normalizeString(event["scope_path"] ?? "") === scopePath,
    );
    const checkpointIds = Object.entries(checkpoints)
      .filter(
        ([, checkpoint]) =>
          isDict(checkpoint) &&
          scopeEvents.some(
            (event) =>
              normalizeString(event["writer_id"] ?? "") ===
              normalizeString((checkpoint as Dict)["writer_id"] ?? ""),
          ),
      )
      .map(([id]) => id)
      .sort(compareCodePoints);
    const sourceEventIds = [
      ...new Set(
        scopeEvents
          .map((event) => normalizeString(event["event_id"] ?? ""))
          .filter((id) => id),
      ),
    ].sort(compareCodePoints);

    for (const rawView of [
      buildChildrenView(scopePath, entries, sourceEventIds, checkpointIds),
      buildCountsView(scopePath, entries, sourceEventIds, checkpointIds),
      buildRecentActivityView(scopePath, scopeEvents, checkpointIds),
    ]) {
      rawView["view_hash"] = computeViewHash(rawView);
      const normalized = normalizeCanonicalView(rawView, {
        viewManifest: { local_only_view_types: [...LOCAL_ONLY_VIEW_TYPES].sort(compareCodePoints) },
      });
      if (normalized) views[String(normalized["view_id"])] = normalized;
    }
  }

  index0.view_manifest = normalizeViewManifest({
    version: 1,
    canonical_view_types: [...INDEX0_CANONICAL_VIEW_TYPES],
    local_only_view_types: [...LOCAL_ONLY_VIEW_TYPES].sort(compareCodePoints),
    builder_versions: Object.fromEntries(
      INDEX0_CANONICAL_VIEW_TYPES.map((viewType) => [viewType, 1]),
    ),
  });
  const sortedViews: Record<string, Dict> = {};
  for (const key of Object.keys(views).sort(compareCodePoints)) sortedViews[key] = views[key]!;
  index0.canonical_views = sortedViews;
  index0.stats = recomputeIndex0Stats(index0);
  (out["_system"] as Dict)["index0"] = index0;
  return out;
}

export function compactIndex0Payload(
  payload: unknown,
  options: { maxCheckpointsPerWriter?: number; fingerprintDir?: string | null } = {},
): Dict {
  const out = ensureIndex0Payload(payload);
  (out["_system"] as Dict)["index0"] = compactIndex0((out["_system"] as Dict)["index0"], {
    ...(options.maxCheckpointsPerWriter !== undefined && {
      maxCheckpointsPerWriter: options.maxCheckpointsPerWriter,
    }),
  });
  return rebuildCanonicalViewsPayload(out, {
    ...(options.fingerprintDir !== undefined && { fingerprintDir: options.fingerprintDir }),
  });
}

/** The index0 summary that goes into a sync manifest. */
export function buildManifestIndex0Metadata(
  payload: unknown,
  options: { checkpointLimit?: number; fingerprintDir?: string | null } = {},
): Dict {
  const limit = options.checkpointLimit ?? INDEX0_MANIFEST_CHECKPOINT_LIMIT;
  const compacted = compactIndex0Payload(payload, {
    ...(options.fingerprintDir !== undefined && { fingerprintDir: options.fingerprintDir }),
  });
  const index0 = (compacted["_system"] as Dict)["index0"] as unknown as Index0;
  const checkpoints = Object.values(index0.checkpoints).filter(isDict);
  const selected = [...checkpoints]
    .sort((a, b) => {
      const ats = safeInt(a["modified_ts"] ?? 0);
      const bts = safeInt(b["modified_ts"] ?? 0);
      if (ats !== bts) return bts - ats;
      return compareCodePoints(
        normalizeString(b["checkpoint_id"] ?? ""),
        normalizeString(a["checkpoint_id"] ?? ""),
      );
    })
    .slice(0, Math.max(0, limit));
  const checkpointIds = selected
    .map((checkpoint) => normalizeString(checkpoint["checkpoint_id"] ?? ""))
    .filter((id) => id);

  const checkpointHashes: Dict = {};
  for (const id of checkpointIds) {
    const checkpoint = index0.checkpoints[id];
    if (checkpoint) checkpointHashes[id] = normalizeString(checkpoint["summary_hash"] ?? "");
  }
  const streamHeads: Dict = {};
  for (const writerId of Object.keys(index0.heads).sort(compareCodePoints)) {
    const head = index0.heads[writerId]!;
    const hash = normalizeString(head["head_hash"] ?? "");
    if (hash) streamHeads[writerId] = hash;
  }
  return {
    schema_version: INDEX0_SCHEMA_VERSION,
    checkpoint_ids: checkpointIds,
    checkpoint_hashes: checkpointHashes,
    stream_heads: streamHeads,
  };
}

export function listCanonicalViews(index0: unknown): Dict[] {
  const normalized = normalizeIndex0(index0);
  return Object.keys(normalized.canonical_views)
    .sort(compareCodePoints)
    .map((key) => normalized.canonical_views[key]!);
}

export function getCanonicalView(
  index0: unknown,
  options: { viewType: string; scopePath: string },
): Dict | null {
  const normalized = normalizeIndex0(index0);
  const viewId = `${normalizeString(options.viewType)}:${normalizeString(options.scopePath)}`;
  const view = normalized.canonical_views[viewId];
  return isDict(view) ? { ...view } : null;
}

// ------------------------------------------------------------------- merge

/**
 * Later timestamp wins; equal timestamps break on the record's own hash.
 *
 * The hash tie-break is what makes the merge deterministic across replicas —
 * both sides compute the same winner without talking to each other.
 */
function preferHashedRecord(current: Dict, incoming: Dict, hashField: string): boolean {
  const curTs = safeInt(current["modified_ts"] ?? 0);
  const incTs = safeInt(incoming["modified_ts"] ?? 0);
  if (incTs !== curTs) return incTs > curTs;
  return (
    compareCodePoints(
      normalizeString(incoming[hashField] ?? ""),
      normalizeString(current[hashField] ?? ""),
    ) > 0
  );
}

export function mergeSystemIndex0(current: unknown, incoming: unknown): Index0 {
  const cur = normalizeIndex0(current);
  const inc = normalizeIndex0(incoming);

  const events: Record<string, Dict> = { ...cur.events };
  for (const [eventId, event] of Object.entries(inc.events)) {
    const existing = events[eventId];
    if (!existing) {
      events[eventId] = event;
      continue;
    }
    if (canonicalJson(existing) === canonicalJson(event)) continue;
    // Two different events claiming one id: pick by hash so both replicas
    // reach the same answer.
    if (compareCodePoints(canonicalHash(event), canonicalHash(existing)) > 0) {
      events[eventId] = event;
    }
  }

  const checkpoints: Record<string, Dict> = { ...cur.checkpoints };
  for (const [id, checkpoint] of Object.entries(inc.checkpoints)) {
    const existing = checkpoints[id];
    if (!existing || preferHashedRecord(existing, checkpoint, "summary_hash")) {
      checkpoints[id] = checkpoint;
    }
  }

  const union = (a: unknown, b: unknown): string[] => {
    const out = new Set<string>();
    for (const list of [a, b]) {
      if (Array.isArray(list)) for (const item of list) out.add(String(item));
    }
    return [...out].sort(compareCodePoints);
  };
  const viewManifest = normalizeViewManifest({
    version: Math.max(
      safeInt(cur.view_manifest["version"] ?? 1, 1),
      safeInt(inc.view_manifest["version"] ?? 1, 1),
    ),
    canonical_view_types: union(
      cur.view_manifest["canonical_view_types"],
      inc.view_manifest["canonical_view_types"],
    ),
    local_only_view_types: union(
      cur.view_manifest["local_only_view_types"],
      inc.view_manifest["local_only_view_types"],
    ),
    builder_versions: {
      ...normalizeMapping(cur.view_manifest["builder_versions"]),
      ...normalizeMapping(inc.view_manifest["builder_versions"]),
    },
  });

  const views: Record<string, Dict> = { ...cur.canonical_views };
  for (const [viewId, view] of Object.entries(inc.canonical_views)) {
    const normalized = normalizeCanonicalView(view, { viewManifest });
    if (!normalized) continue;
    const existing = views[viewId];
    if (!existing || preferHashedRecord(existing, normalized, "view_hash")) {
      views[viewId] = normalized;
    }
  }

  const heads: Record<string, Dict> = { ...cur.heads };
  for (const [writerId, head] of Object.entries(inc.heads)) {
    const existing = heads[writerId];
    if (!existing || preferHashedRecord(existing, head, "head_hash")) {
      heads[writerId] = head;
    }
  }

  const sortRecords = (source: Record<string, Dict>): Record<string, Dict> => {
    const out: Record<string, Dict> = {};
    for (const key of Object.keys(source).sort(compareCodePoints)) out[key] = source[key]!;
    return out;
  };

  const merged: Index0 = {
    schema_version: Math.max(cur.schema_version, inc.schema_version),
    events: sortRecords(events),
    checkpoints: sortRecords(checkpoints),
    canonical_views: sortRecords(views),
    view_manifest: viewManifest,
    heads: sortRecords(heads),
    stats: {},
  };
  merged.stats = recomputeIndex0Stats(merged);
  return merged;
}
