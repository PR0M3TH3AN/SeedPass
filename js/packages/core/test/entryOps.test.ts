/**
 * Entry-creation parity: rebuild the Python EntryManager-generated fixture
 * index from scratch with the same calls and a pinned clock, and require
 * deep equality. Any drift in field shapes, index allocation, or timestamp
 * formatting fails here.
 */

import { describe, expect, it } from "vitest";
import { entriesIndex, mnemonics } from "@seedpass/test-vectors";
import {
  addPasswordEntry,
  addTotpDeterministic,
  addTotpImported,
  addSshKeyEntry,
  addNostrKeyEntry,
  addKeyValueEntry,
  addDocumentEntry,
  addSeedEntry,
  addManagedAccountEntry,
  addPgpKeyEntry,
  parseVaultIndex,
  type Clock,
  type VaultIndex,
} from "@seedpass/core";

const FIXED_UNIX = 1700000000;
const clock: Clock = { nowUnix: () => FIXED_UNIX };
const MNEMONIC = mnemonics["abandon12"]!;

describe("entry creation parity", () => {
  it("rebuilds the fixture index byte-for-byte", () => {
    const index = { schema_version: 4, entries: {} } as unknown as VaultIndex;

    // Mirrors scripts/generate_ts_port_fixtures.py::_build_entries_index
    addPasswordEntry(index, "example.com", 16, {
      username: "alice",
      url: "https://example.com",
      notes: "password note",
      tags: ["web"],
      clock,
    });
    addTotpDeterministic(index, "example-totp", MNEMONIC, { tags: ["otp"], clock });
    addTotpImported(index, "imported-totp", "JBSWY3DPEHPK3PXP", {
      period: 45,
      digits: 8,
      clock,
    });
    addSshKeyEntry(index, "example-ssh", { notes: "ssh note", clock });
    addNostrKeyEntry(index, "example-nostr", { clock });
    addKeyValueEntry(index, "api-token", "token", "abc123", { tags: ["api"], clock });
    addDocumentEntry(index, "example-doc", "hello fixture world", { clock });
    addSeedEntry(index, "example-seed", { wordCount: 24, clock });
    addManagedAccountEntry(index, "example-managed", MNEMONIC, { clock });
    addPgpKeyEntry(index, "example-pgp", { userId: "fixture@example.com", clock });

    expect(JSON.parse(JSON.stringify(index))).toEqual(entriesIndex.entries);
  });

  it("produces schema-valid entries", () => {
    const index = { schema_version: 4, entries: {} } as unknown as VaultIndex;
    addPasswordEntry(index, "x.com", 20, { clock });
    addTotpDeterministic(index, "x-totp", MNEMONIC, { clock });
    expect(() => parseVaultIndex(JSON.parse(JSON.stringify(index)))).not.toThrow();
  });

  it("allocates ids and totp derivation indices independently", () => {
    const index = { schema_version: 4, entries: {} } as unknown as VaultIndex;
    addPasswordEntry(index, "a", 16, { clock });
    addPasswordEntry(index, "b", 16, { clock });
    const totpId = addTotpDeterministic(index, "t1", MNEMONIC, { clock });
    expect(totpId).toBe("2");
    const entry = (index.entries as Record<string, { index?: number }>)["2"]!;
    expect(entry.index).toBe(0); // first TOTP derivation index despite id 2
    addTotpDeterministic(index, "t2", MNEMONIC, { clock });
    const entry2 = (index.entries as Record<string, { index?: number }>)["3"]!;
    expect(entry2.index).toBe(1);
  });

  it("rejects invalid imported TOTP secrets", () => {
    const index = { schema_version: 4, entries: {} } as unknown as VaultIndex;
    expect(() => addTotpImported(index, "bad", "not base32!", { clock })).toThrow(
      "Invalid TOTP secret",
    );
  });
});

import { mergeIndexPayloads, Bip85 } from "@seedpass/core";

describe("index allocation watermark", () => {
  function freshIndex(): VaultIndex {
    return { schema_version: 4, entries: {} } as VaultIndex;
  }

  it("does not recycle an id deleted through a merge", () => {
    // An entry id is a permanent BIP-85 derivation coordinate: reissuing a
    // deleted #2 would hand a NEW entry the departed identity's exact child
    // seed and npub.
    const index = freshIndex();
    addPasswordEntry(index, "web-a", 20, { clock });
    addPasswordEntry(index, "web-b", 20, { clock });
    const managedId = addManagedAccountEntry(index, "alice", MNEMONIC, { clock });
    expect(managedId).toBe("2");
    const departedSeed = Bip85.fromMnemonic(MNEMONIC).deriveMnemonic(2, 12);

    const incoming = {
      schema_version: 4,
      entries: {
        "2": { kind: "managed_account", label: "alice", modified_ts: FIXED_UNIX + 10, _deleted: true },
      },
    };
    const merged = parseVaultIndex(
      mergeIndexPayloads(index as unknown as Record<string, unknown>, incoming, "remote"),
    );
    expect(merged.entries["2"]).toBeUndefined();

    const newId = addManagedAccountEntry(merged, "bob", MNEMONIC, { clock });
    expect(newId).toBe("3"); // NOT the tombstoned 2
    const bobSeed = Bip85.fromMnemonic(MNEMONIC).deriveMnemonic(3, 12);
    expect(bobSeed).not.toBe(departedSeed);
  });

  it("merge carries the higher watermark even with no entries or tombstones behind it", () => {
    const current = {
      schema_version: 4,
      entries: { "0": { kind: "password", label: "a", modified_ts: 50 } },
      _sync_meta: { next_index: 500 },
    };
    const merged = mergeIndexPayloads(current, { schema_version: 4, entries: {} }, "x");
    expect((merged["_sync_meta"] as Record<string, unknown>)["next_index"]).toBe(500);
  });

  it("an explicit high index pushes the watermark past it", () => {
    const index = freshIndex();
    addManagedAccountEntry(index, "pinned", MNEMONIC, { clock, index: 40 });
    const nextId = addPasswordEntry(index, "after", 20, { clock });
    expect(nextId).toBe("41");
  });

  it("a legacy vault heals from tombstones still in retention", () => {
    // Pre-watermark vault: no _sync_meta.next_index, but a tombstone for #7.
    const legacy = freshIndex();
    addPasswordEntry(legacy, "a", 20, { clock }); // id 0
    const container = legacy as unknown as Record<string, unknown>;
    container["_sync_meta"] = {
      tombstones: { "7": { deleted_ts: 60, entry_hash: "", event_hash: "" } },
    };
    const id = addPasswordEntry(legacy, "fresh", 20, { clock });
    expect(id).toBe("8"); // past the tombstone, not max(live)+1 = 1
  });
});
