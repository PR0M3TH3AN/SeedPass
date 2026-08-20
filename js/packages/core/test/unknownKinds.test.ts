/**
 * Unknown-kind passthrough (spec §8.2): a record whose kind this build does
 * not understand is carried through verbatim — never dropped, never a parse
 * failure that bricks the whole vault. The counterweight: this must not
 * become a validation bypass, so a malformed record of a KNOWN kind still
 * fails loudly.
 */

import { describe, expect, it } from "vitest";
import {
  parseVaultIndex,
  addPasswordEntry,
  encryptV3,
  decryptPayload,
  deriveIndexKeyBytes,
  utf8,
  type VaultIndex,
} from "@seedpass/core";
import { mnemonics } from "@seedpass/test-vectors";

const MNEMONIC = mnemonics["abandon12"]!;

/** A record shaped like something a future identity client would write. */
const FOREIGN_RECORD = {
  kind: "bitlogin_org",
  type: "bitlogin_org",
  label: "Acme Corporation",
  modified_ts: 1700000123,
  bitlogin: {
    admins: ["npub1aaaa"],
    roles: { sales: ["npub1bbbb"] },
    policy_rev: 7,
  },
};

function indexWithForeignRecord(): Record<string, unknown> {
  return {
    schema_version: 4,
    entries: {
      "0": {
        type: "key_value",
        kind: "key_value",
        label: "api",
        key: "k",
        value: "v",
        archived: false,
        notes: "",
        tags: [],
        links: [],
      },
      "1": FOREIGN_RECORD,
    },
  };
}

describe("unknown entry kinds pass through", () => {
  it("parses an index containing a foreign record and preserves it verbatim", () => {
    const index = parseVaultIndex(indexWithForeignRecord());
    expect(index.entries["1"]).toEqual(FOREIGN_RECORD);
    // The known record beside it still validated normally.
    expect(index.entries["0"]!.kind).toBe("key_value");
  });

  it("survives a full encrypt → decrypt → parse → re-encrypt round trip", async () => {
    const key = deriveIndexKeyBytes(MNEMONIC);
    const blob = await encryptV3(key, utf8(JSON.stringify(indexWithForeignRecord())));
    const first = parseVaultIndex(JSON.parse(new TextDecoder().decode(await decryptPayload(key, blob))));
    // What saveVault does before writing: re-validate without migration.
    const revalidated = parseVaultIndex(JSON.parse(JSON.stringify(first)), { migrate: false });
    const blob2 = await encryptV3(key, utf8(JSON.stringify(revalidated)));
    const second = parseVaultIndex(JSON.parse(new TextDecoder().decode(await decryptPayload(key, blob2))));
    expect(second.entries["1"]).toEqual(FOREIGN_RECORD);
  });

  it("typed operations keep working around the foreign record", () => {
    const index = parseVaultIndex(indexWithForeignRecord());
    // Allocation sees the foreign record's id and does not collide with it.
    const id = addPasswordEntry(index as VaultIndex, "site", 20, {});
    expect(id).toBe("2");
    expect(index.entries["1"]).toEqual(FOREIGN_RECORD);
  });

  it("fills kind from type for foreign records too (legacy shape)", () => {
    const raw = indexWithForeignRecord();
    const entries = raw["entries"] as Record<string, Record<string, unknown>>;
    delete entries["1"]!["kind"];
    const index = parseVaultIndex(raw);
    expect((index.entries["1"] as unknown as Record<string, unknown>)["kind"]).toBe("bitlogin_org");
  });

  it("does NOT let a malformed known kind escape through the passthrough", () => {
    const raw = indexWithForeignRecord();
    (raw["entries"] as Record<string, unknown>)["2"] = {
      kind: "password",
      type: "password",
      label: "broken",
      // length missing: must fail strict validation, not pass as opaque
    };
    expect(() => parseVaultIndex(raw)).toThrow();
  });

  it("still rejects records with no kind or type at all", () => {
    const raw = indexWithForeignRecord();
    (raw["entries"] as Record<string, unknown>)["2"] = { label: "mystery" };
    expect(() => parseVaultIndex(raw)).toThrow();
  });
});
