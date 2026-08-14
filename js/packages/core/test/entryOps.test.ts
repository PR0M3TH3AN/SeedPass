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
