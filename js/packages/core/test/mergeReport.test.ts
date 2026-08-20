/**
 * What a merge resolves silently.
 *
 * The merge is a deterministic CRDT and its outcome is frozen for parity with
 * Python — both implementations must reach the same vault from the same
 * inputs, so the resolution rules are not up for negotiation. What was
 * missing is that the user is never told a resolution happened: an entry they
 * created on one device is simply absent afterwards, with no error and
 * nothing in the summary.
 *
 * The load-bearing test in this file is the last one: passing a report must
 * not change the merged result. If collecting the report could alter the
 * outcome, it would be a parity divergence rather than an observation.
 */

import { describe, expect, it } from "vitest";
import {
  mergeIndexPayloads,
  newMergeReport,
  TOMBSTONE_RETENTION_CAP,
} from "@seedpass/core";

function entry(kind: string, label: string, ts: number, extra: Record<string, unknown> = {}) {
  return {
    kind,
    type: kind,
    label,
    notes: "",
    tags: [],
    archived: false,
    modified_ts: ts,
    ...extra,
  };
}

function index(entries: Record<string, unknown>, extra: Record<string, unknown> = {}) {
  return { schema_version: 4, entries, ...extra };
}

describe("same-id conflicts are reported", () => {
  it("names the kept and discarded entries when two replicas allocate one id", () => {
    // The realistic case: two devices offline, both allocate id 5.
    const local = index({ "5": entry("password", "bank.example", 1700000100, { length: 16 }) });
    const remote = index({ "5": entry("ssh", "deploy-key", 1700000200, { index: 5 }) });

    const report = newMergeReport();
    const merged = mergeIndexPayloads(local, remote, "test", { report }) as {
      entries: Record<string, { label: string }>;
    };

    expect(report.conflicts).toHaveLength(1);
    const conflict = report.conflicts[0]!;
    expect(conflict.id).toBe("5");
    expect(conflict.differentKind).toBe(true);
    // Whichever way the deterministic rules resolve it, the report must
    // describe the actual outcome rather than assume one.
    expect(conflict.kept.label).toBe(merged.entries["5"]!.label);
    expect(conflict.discarded.label).not.toBe(merged.entries["5"]!.label);
    expect([conflict.kept.label, conflict.discarded.label].sort()).toEqual([
      "bank.example",
      "deploy-key",
    ]);
  });

  it("reports a conflict whichever side happens to win", () => {
    // Same pair, opposite timestamps, so the other side survives. Both
    // directions must be reported — a report that only fires when the
    // incoming side wins would miss half of all real losses.
    const older = index({ "5": entry("password", "bank.example", 1700000100, { length: 16 }) });
    const newer = index({ "5": entry("ssh", "deploy-key", 1700000200, { index: 5 }) });

    const forward = newMergeReport();
    mergeIndexPayloads(older, newer, "test", { report: forward });
    const backward = newMergeReport();
    mergeIndexPayloads(newer, older, "test", { report: backward });

    expect(forward.conflicts).toHaveLength(1);
    expect(backward.conflicts).toHaveLength(1);
  });

  it("stays quiet when both sides hold the same entry at different times", () => {
    // An ordinary edit — the overwhelmingly common case. Reporting it would
    // bury the case that matters in noise and train the user to ignore it.
    const local = index({ "5": entry("password", "bank.example", 1700000100, { length: 16 }) });
    const remote = index({
      "5": entry("password", "bank.example", 1700000200, { length: 24 }),
    });
    const report = newMergeReport();
    mergeIndexPayloads(local, remote, "test", { report });
    expect(report.conflicts).toEqual([]);
  });

  it("reports a same-kind conflict when the labels genuinely differ", () => {
    const local = index({ "5": entry("password", "bank.example", 1700000100, { length: 16 }) });
    const remote = index({ "5": entry("password", "forum.example", 1700000200, { length: 16 }) });
    const report = newMergeReport();
    mergeIndexPayloads(local, remote, "test", { report });
    expect(report.conflicts).toHaveLength(1);
    expect(report.conflicts[0]!.differentKind).toBe(false);
  });

  it("stays quiet on a merge with no id overlap", () => {
    const local = index({ "1": entry("password", "a", 1700000100, { length: 16 }) });
    const remote = index({ "2": entry("password", "b", 1700000200, { length: 16 }) });
    const report = newMergeReport();
    const merged = mergeIndexPayloads(local, remote, "test", { report }) as {
      entries: Record<string, unknown>;
    };
    expect(report.conflicts).toEqual([]);
    expect(Object.keys(merged.entries).sort()).toEqual(["1", "2"]);
  });
});

describe("tombstone eviction is reported", () => {
  it("counts deletions forgotten at the retention cap", () => {
    // Past the cap the oldest deletions are dropped, and merging a stale
    // replica then resurrects those entries. The user cannot otherwise know
    // their deletion history has started to roll off.
    const tombstones: Record<string, unknown> = {};
    const overflow = 5;
    for (let i = 0; i < TOMBSTONE_RETENTION_CAP + overflow; i++) {
      tombstones[String(i)] = {
        deleted_ts: 1700000000 + i,
        entry_hash: "",
        event_hash: "",
        source: "test",
      };
    }
    const local = index({}, { _sync_meta: { tombstones } });
    const report = newMergeReport();
    mergeIndexPayloads(local, index({}), "test", { report });
    expect(report.tombstonesEvicted).toBe(overflow);
  });

  it("reports nothing when the cap has not been reached", () => {
    const local = index(
      {},
      {
        _sync_meta: {
          tombstones: {
            "1": { deleted_ts: 1700000000, entry_hash: "", event_hash: "", source: "t" },
          },
        },
      },
    );
    const report = newMergeReport();
    mergeIndexPayloads(local, index({}), "test", { report });
    expect(report.tombstonesEvicted).toBe(0);
  });
});

describe("observing the merge does not change it", () => {
  it("produces a byte-identical result with and without a report", () => {
    // This is the parity guarantee. The merged vault must not depend on
    // whether anyone was watching — otherwise the two implementations could
    // reach different vaults from the same inputs, which is the one thing
    // the deterministic merge exists to prevent.
    const local = index(
      {
        "1": entry("password", "kept", 1700000100, { length: 16 }),
        "5": entry("password", "loser", 1700000100, { length: 16 }),
      },
      {
        _sync_meta: {
          next_index: 6,
          tombstones: {
            "9": { deleted_ts: 1700000050, entry_hash: "", event_hash: "", source: "t" },
          },
        },
      },
    );
    const remote = index(
      {
        "5": entry("ssh", "winner", 1700000200, { index: 5 }),
        "7": entry("totp", "extra", 1700000300, { index: 7, period: 30, digits: 6 }),
      },
      { _sync_meta: { next_index: 8, tombstones: {} } },
    );

    const withReport = mergeIndexPayloads(local, remote, "test", {
      report: newMergeReport(),
    });
    const withoutReport = mergeIndexPayloads(local, remote, "test");
    expect(JSON.stringify(withReport)).toBe(JSON.stringify(withoutReport));
  });
});
