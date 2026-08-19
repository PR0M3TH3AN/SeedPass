/**
 * index0 / atlas.
 *
 * This is derived state whose whole contract is hash parity: event ids,
 * integrity hashes, checkpoint summaries and view hashes are SHA-256 over
 * Python's canonical JSON, and the merge picks winners by comparing those
 * hashes. One byte of disagreement in the encoding means the two
 * implementations permanently disagree about which record wins.
 *
 * So the load-bearing tests compare whole structures against fixtures the
 * Python implementation produced, via canonicalJson rather than toEqual —
 * an assertion that passes only if the bytes that get hashed are identical.
 */

import { describe, expect, it } from "vitest";
import {
  appendIndex0Event,
  compactIndex0Payload,
  buildManifestIndex0Metadata,
  mergeSystemIndex0,
  deriveIndex0Context,
  listCanonicalViews,
  getCanonicalView,
  normalizeIndex0,
  normalizeIndex0Event,
  rebuildCanonicalViewsPayload,
  emitEntryEvents,
  canonicalJson,
  LOCAL_ONLY_VIEW_TYPES,
} from "@seedpass/core";
import { index0Fixture as fx } from "@seedpass/test-vectors";

const FP = "/home/user/.seedpass/C557EEC878DFD852";
const MANAGED = "/home/user/.seedpass/C557EEC878DFD852/accounts/AABBCCDDEEFF0011";

/** Rebuild the fixture's event stream, event for event. */
function buildAppended(): Record<string, unknown> {
  let payload: unknown = { schema_version: 4, entries: fx.entries };
  const specs = [
    [1700000100, "entry.created", "0", "password"],
    [1700000200, "entry.created", "1", "totp"],
    [1700086400, "entry.updated", "0", "password"],
    [1700086500, "entry.archived", "1", "totp"],
  ] as const;
  specs.forEach(([ts, eventType, subjectId, subjectKind], i) => {
    payload = appendIndex0Event(payload, {
      eventType,
      subjectType: "entry",
      subjectId,
      subjectKind,
      modifiedTs: ts,
      fingerprintDir: FP,
      tags: ["auto"],
      summary: `event ${i} — ünï`,
    });
  });
  return appendIndex0Event(payload, {
    eventType: "entry.created",
    subjectType: "entry",
    subjectId: "7",
    subjectKind: "seed",
    modifiedTs: 1700090000,
    fingerprintDir: MANAGED,
  });
}

describe("byte-for-byte parity with Python", () => {
  it("derives the same writer context, including managed accounts", () => {
    expect(deriveIndex0Context(FP)).toEqual(fx.context_root);
    // A managed account's scope names both the root and the child, so views
    // from a parent and its child cannot collide.
    expect(deriveIndex0Context(MANAGED)).toEqual(fx.context_managed);
  });

  it("produces an identical event stream, hashes and heads", () => {
    // Every event id is a hash of the event, and each chains onto the
    // writer's previous head — so this passing means the canonical encoding,
    // the field set and the chaining all match.
    expect(canonicalJson(buildAppended())).toBe(canonicalJson(fx.appended));
  });

  it("compacts to identical checkpoints and views", () => {
    const compacted = compactIndex0Payload(buildAppended(), { fingerprintDir: FP });
    expect(canonicalJson(compacted)).toBe(canonicalJson(fx.compacted));
  });

  it("produces identical manifest metadata", () => {
    expect(
      canonicalJson(buildManifestIndex0Metadata(buildAppended(), { fingerprintDir: FP })),
    ).toBe(canonicalJson(fx.manifest_meta));
  });

  it("merges two replicas to an identical result", () => {
    const compacted = compactIndex0Payload(buildAppended(), { fingerprintDir: FP });
    const mine = (compacted as Record<string, any>)["_system"].index0;
    const theirs = (fx.other as Record<string, any>)["_system"].index0;
    expect(canonicalJson(mergeSystemIndex0(mine, theirs))).toBe(canonicalJson(fx.merged));
  });

  it("lists and fetches views identically", () => {
    const index0 = (compactIndex0Payload(buildAppended(), { fingerprintDir: FP }) as Record<
      string,
      any
    >)["_system"].index0;
    expect(canonicalJson(listCanonicalViews(index0))).toBe(canonicalJson(fx.views));
    expect(
      canonicalJson(
        getCanonicalView(index0, {
          viewType: "counts_by_kind",
          scopePath: fx.context_root["scope_path"]!,
        }),
      ),
    ).toBe(canonicalJson(fx.one_view));
  });
});

describe("normalization refuses what it cannot place", () => {
  it("drops events with no usable timestamp", () => {
    // A timestamp is what orders the stream; without one the event cannot be
    // placed, and guessing would corrupt the ordering silently.
    for (const bad of [0, -1, "", "abc", null]) {
      expect(normalizeIndex0Event({ event_type: "x", subject_type: "entry", subject_id: "1", writer_id: "w", modified_ts: bad })).toBeNull();
    }
  });

  it("drops events missing a required field", () => {
    const base = {
      event_type: "entry_created",
      subject_type: "entry",
      subject_id: "1",
      writer_id: "writer:profile:AAAA",
      modified_ts: 1700000000,
    };
    expect(normalizeIndex0Event(base)).not.toBeNull();
    for (const field of ["event_type", "subject_type", "subject_id", "writer_id"]) {
      expect(normalizeIndex0Event({ ...base, [field]: "" })).toBeNull();
    }
  });

  it("preserves a stored integrity hash even when it disagrees", () => {
    // This normalizes; it does not verify. Rewriting a mismatched hash would
    // hide exactly the tampering the hash exists to reveal.
    const event = normalizeIndex0Event({
      event_type: "entry_created",
      subject_type: "entry",
      subject_id: "1",
      writer_id: "w",
      modified_ts: 1700000000,
      integrity_hash: "deadbeef",
    })!;
    expect(event["integrity_hash"]).toBe("deadbeef");
  });

  it("never admits a local-only view into shared state", () => {
    // These are derived from data that does not leave the machine, so
    // syncing them would publish inferences about it.
    for (const viewType of LOCAL_ONLY_VIEW_TYPES) {
      const normalized = normalizeIndex0({
        canonical_views: {
          "x:y": { view_id: "x:y", view_type: viewType, modified_ts: 1700000000 },
        },
      });
      expect(normalized.canonical_views).toEqual({});
    }
  });

  it("survives a malformed entry id rather than failing to build views", () => {
    // A vault that will not open is indistinguishable from one that is lost,
    // so a hand-edited id degrades the ordering instead of throwing.
    const rebuilt = rebuildCanonicalViewsPayload(
      { entries: { "2": { kind: "password", label: "b" }, "not-a-number": { kind: "password", label: "a" } } },
      { fingerprintDir: FP },
    );
    const view = getCanonicalView((rebuilt as any)._system.index0, {
      viewType: "children_of",
      scopePath: deriveIndex0Context(FP).scope_path,
    })!;
    const ids = ((view["data"] as any).children as any[]).map((c) => c.entry_id);
    // Numeric ids first, non-numeric after — the fixture proves Python agrees.
    expect(ids).toEqual(["2", "not-a-number"]);
  });

  it("tolerates junk in place of the whole block", () => {
    for (const junk of [null, "string", 42, []]) {
      const normalized = normalizeIndex0(junk);
      expect(normalized.events).toEqual({});
      expect(normalized.stats["event_count"]).toBe(0);
    }
  });
});

describe("the differ records what a mutation changed", () => {
  const base = { schema_version: 4, entries: {} as Record<string, unknown> };

  it("emits create, update and delete with Python's vocabulary", () => {
    const before = { "0": { kind: "password", label: "a", modified_ts: 1700000000 } };
    const after = {
      "0": { kind: "password", label: "renamed", modified_ts: 1700000500 },
      "1": { kind: "totp", label: "new", modified_ts: 1700000600 },
    };
    const out = emitEntryEvents(
      { ...base, entries: after, _system: { index0: { events: {} } } },
      { before, after, fingerprintDir: FP, now: 1700000700 },
    );
    const events = Object.values((out as any)._system.index0.events) as any[];
    const byType = events.map((e) => e.event_type).sort();
    expect(byType).toEqual(["entry_created", "entry_updated"]);

    const deleted = emitEntryEvents(
      { ...base, entries: {}, _system: { index0: { events: {} } } },
      { before, after: {}, fingerprintDir: FP, now: 1700000700 },
    );
    const deletedEvents = Object.values((deleted as any)._system.index0.events) as any[];
    expect(deletedEvents[0].event_type).toBe("entry_deleted");
    expect(deletedEvents[0].subject_id).toBe("0");
  });

  it("emits nothing when nothing changed", () => {
    const entries = { "0": { kind: "password", label: "a", modified_ts: 1700000000 } };
    const out = emitEntryEvents(
      { ...base, entries, _system: { index0: { events: {} } } },
      { before: entries, after: entries, fingerprintDir: FP, now: 1700000700 },
    );
    expect(Object.keys((out as any)._system.index0.events)).toHaveLength(0);
  });

  it("emits in a deterministic order, so two replicas agree", () => {
    const after = {
      "10": { kind: "password", label: "j", modified_ts: 1700000010 },
      "2": { kind: "password", label: "b", modified_ts: 1700000002 },
      "1": { kind: "password", label: "a", modified_ts: 1700000001 },
    };
    const run = () =>
      canonicalJson(
        emitEntryEvents(
          { ...base, entries: after, _system: { index0: { events: {} } } },
          { before: {}, after, fingerprintDir: FP, now: 1700000700 },
        ),
      );
    expect(run()).toBe(run());
  });
});
