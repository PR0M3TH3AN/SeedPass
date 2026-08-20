/**
 * Emit index0 events for whatever a vault mutation actually changed.
 *
 * Python emits from each call site in EntryManager, naming the operation it
 * just performed. This derives the events by comparing the index before and
 * after instead, and is wired into the single mutation funnel every surface
 * goes through (CLI, TUI, API).
 *
 * That is a deliberate difference, for one reason: a call-site emitter is
 * something a new code path can forget, and a silently incomplete activity
 * ledger is worse than an absent one — it reads as "nothing happened". A
 * funnel-level differ cannot be forgotten, because there is nowhere else to
 * write a change from. The event VOCABULARY matches Python's
 * (entry_created / entry_updated / entry_deleted), so a stream from either
 * implementation reads the same.
 */

import { appendIndex0Event, type Dict } from "./index0.js";

function isDict(value: unknown): value is Dict {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function kindOf(entry: Dict): string {
  return String(entry["kind"] ?? entry["type"] ?? "").trim() || "entry";
}

function tsOf(entry: Dict, fallback: number): number {
  const raw = Number(entry["modified_ts"] ?? 0);
  return Number.isFinite(raw) && raw > 0 ? Math.trunc(raw) : fallback;
}

export interface EmitOptions {
  /** Entries as they were before the mutation. */
  before: Record<string, unknown>;
  /** Entries as they are after it. */
  after: Record<string, unknown>;
  fingerprintDir: string;
  /** Seconds since the epoch, for entries carrying no timestamp of their own. */
  now: number;
}

/**
 * Append one event per changed entry, returning the updated payload.
 *
 * Comparison is by canonical JSON of the whole entry, so a change to any
 * field counts — including ones no specific call site would have thought to
 * report.
 */
export function emitEntryEvents(payload: unknown, options: EmitOptions): Dict {
  const { before, after, fingerprintDir, now } = options;
  let out = payload as Dict;

  const ids = new Set([...Object.keys(before), ...Object.keys(after)]);
  // Sorted so the emitted order is deterministic: two replicas performing the
  // same batch must produce the same stream.
  for (const id of [...ids].sort((a, b) => {
    const an = Number(a);
    const bn = Number(b);
    if (Number.isInteger(an) && Number.isInteger(bn)) return an - bn;
    return a < b ? -1 : a > b ? 1 : 0;
  })) {
    const oldEntry = before[id];
    const newEntry = after[id];
    const had = isDict(oldEntry);
    const has = isDict(newEntry);
    if (!had && !has) continue;

    if (has && !had) {
      out = appendIndex0Event(out, {
        eventType: "entry_created",
        subjectType: "entry",
        subjectId: id,
        subjectKind: kindOf(newEntry),
        modifiedTs: tsOf(newEntry, now),
        fingerprintDir,
        payloadRef: { entry_id: id },
        links: Array.isArray(newEntry["links"]) ? (newEntry["links"] as unknown[]) : [],
        tags: Array.isArray(newEntry["tags"]) ? (newEntry["tags"] as unknown[]) : [],
        summary: `Created ${kindOf(newEntry)} entry`,
        source: "entry_management",
      });
      continue;
    }

    if (had && !has) {
      out = appendIndex0Event(out, {
        eventType: "entry_deleted",
        subjectType: "entry",
        subjectId: id,
        subjectKind: kindOf(oldEntry),
        modifiedTs: now,
        fingerprintDir,
        payloadRef: { entry_id: id },
        summary: `Deleted ${kindOf(oldEntry)} entry`,
        source: "entry_management",
      });
      continue;
    }

    if (had && has && JSON.stringify(oldEntry) !== JSON.stringify(newEntry)) {
      out = appendIndex0Event(out, {
        eventType: "entry_updated",
        subjectType: "entry",
        subjectId: id,
        subjectKind: kindOf(newEntry),
        modifiedTs: tsOf(newEntry, now),
        fingerprintDir,
        payloadRef: { entry_id: id },
        links: Array.isArray(newEntry["links"]) ? (newEntry["links"] as unknown[]) : [],
        tags: Array.isArray(newEntry["tags"]) ? (newEntry["tags"] as unknown[]) : [],
        summary: `Updated ${kindOf(newEntry)} entry`,
        source: "entry_management",
      });
    }
  }
  return out;
}
