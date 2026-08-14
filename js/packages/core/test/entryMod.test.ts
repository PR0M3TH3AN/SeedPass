/**
 * Modification parity: replay the exact op sequence the Python EntryManager
 * performed in the entry_mods fixture and require byte-for-byte equality.
 */

import { describe, expect, it } from "vitest";
import { entriesIndex, entryMods } from "@seedpass/test-vectors";
import {
  modifyEntry,
  archiveEntry,
  restoreEntry,
  addLink,
  removeLink,
  getLinks,
  normalizeLinks,
  type Clock,
  type VaultIndex,
} from "@seedpass/core";

const modClock: Clock = { nowUnix: () => entryMods.mod_unix };

function creationState(): VaultIndex {
  return JSON.parse(JSON.stringify(entriesIndex.entries)) as VaultIndex;
}

describe("entry modification parity", () => {
  it("replays the Python modification sequence byte-for-byte", () => {
    const index = creationState();

    // Mirrors gen_entry_mods in scripts/generate_ts_port_fixtures.py
    modifyEntry(
      index,
      "0",
      {
        username: "alice2",
        url: "https://example.org",
        notes: "updated note",
        tags: ["web", "prod"],
        min_digits: 3,
        special_mode: "safe",
      },
      modClock,
    );
    modifyEntry(index, "1", { period: 60, digits: 8 }, modClock);
    modifyEntry(index, "5", { label: "api-token-renamed", value: "rotated-value" }, modClock);
    archiveEntry(index, "6", modClock);
    restoreEntry(index, "6", modClock);
    archiveEntry(index, "3", modClock);
    addLink(index, "0", 1, { relation: "totp", note: "2fa for site", clock: modClock });
    addLink(index, "0", 5, { relation: "related_to", clock: modClock });
    addLink(index, "5", 0, { clock: modClock });
    removeLink(index, "0", 5, { clock: modClock });

    expect(JSON.parse(JSON.stringify(index))).toEqual(entryMods.entries);
  });

  it("rejects fields the entry kind does not allow", () => {
    const index = creationState();
    expect(() => modifyEntry(index, "1", { username: "x" }, modClock)).toThrow(
      /does not support fields: username/,
    );
    expect(() => modifyEntry(index, "0", { period: 60 }, modClock)).toThrow(
      /does not support fields: period/,
    );
  });

  it("refuses self-referential links and missing targets", () => {
    const index = creationState();
    expect(() => addLink(index, "0", 0, { clock: modClock })).toThrow("Self-referential");
    expect(() => addLink(index, "0", 99, { clock: modClock })).toThrow("Entry not found");
  });

  it("resolves link target metadata", () => {
    const index = creationState();
    addLink(index, "0", 1, { relation: "totp", clock: modClock });
    const links = getLinks(index, "0");
    expect(links).toEqual([
      {
        target_id: 1,
        relation: "totp",
        note: "",
        target_label: "example-totp",
        target_kind: "totp",
      },
    ]);
  });

  it("normalizes and dedupes links like Python", () => {
    expect(
      normalizeLinks([
        { target_id: "3", relation: " Related_To ", note: " x " },
        { target_id: 3, relation: "related_to", note: "x" },
        { target_id: -1, relation: "r" },
        { target_id: 4, relation: "" },
        "junk",
      ]),
    ).toEqual([{ target_id: 3, relation: "related_to", note: "x" }]);
  });
});
