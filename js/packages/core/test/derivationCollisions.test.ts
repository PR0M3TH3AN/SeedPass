/**
 * Shared BIP-85 app-32 derivation coordinates.
 *
 * The first test does not exercise the detector at all — it proves the
 * property the detector exists to report, by deriving the keys and comparing
 * the bytes. Without that, the detector is a rule someone wrote down, and a
 * change to the derivation could make it wrong while every other test here
 * still passed.
 */

import { describe, expect, it } from "vitest";
import {
  Bip85,
  deriveSshKeyPair,
  derivePgpKey,
  findDerivationCollisions,
  bytesToHex,
  type VaultIndex,
} from "@seedpass/core";
import { mnemonics } from "@seedpass/test-vectors";

const MNEMONIC = mnemonics["abandon12"]!;

function entry(kind: string, label: string, extra: Record<string, unknown> = {}) {
  return {
    kind,
    type: kind,
    label,
    notes: "",
    tags: [],
    archived: false,
    modified_ts: 1700000000,
    ...extra,
  };
}

function vault(entries: Record<string, unknown>): VaultIndex {
  return { schema_version: 4, entries } as unknown as VaultIndex;
}

describe("the property being reported is real", () => {
  it("ssh@N and pgp@N are byte-for-byte the same private key", () => {
    const INDEX = 7;
    const ssh = deriveSshKeyPair(MNEMONIC, INDEX);
    const pgp = derivePgpKey(MNEMONIC, INDEX, { userId: "x" });
    // Both take 32 bytes of m/83696968'/32'/7'. Not "related" — identical.
    expect(bytesToHex(ssh.privateKey)).toBe(bytesToHex(pgp.privateKey));
  });

  it("password@N takes that same key as its entropy prefix", () => {
    const INDEX = 7;
    const ssh = deriveSshKeyPair(MNEMONIC, INDEX);
    const bip85 = Bip85.fromMnemonic(MNEMONIC);
    // The password path asks for 64 bytes at the same coordinate; the first
    // 32 are exactly the SSH/PGP private key. The password stays safe (256
    // unknown bits remain, and PBKDF2 is one-way) — this is a key-separation
    // failure, not a password break.
    const passwordEntropy = bip85.deriveEntropy({
      index: INDEX,
      entropyBytes: 64,
      appNo: 32,
    });
    expect(bytesToHex(passwordEntropy.slice(0, 32))).toBe(bytesToHex(ssh.privateKey));
  });

  it("different indices do not collide", () => {
    expect(bytesToHex(deriveSshKeyPair(MNEMONIC, 7).privateKey)).not.toBe(
      bytesToHex(deriveSshKeyPair(MNEMONIC, 8).privateKey),
    );
  });
});

describe("findDerivationCollisions", () => {
  it("reports ssh/pgp at one index as an identical key", () => {
    const found = findDerivationCollisions(
      vault({
        "3": entry("ssh", "deploy-key", { index: 3 }),
        "4": entry("pgp", "signing-key", { index: 3 }),
      }),
    );
    expect(found).toHaveLength(1);
    expect(found[0]!.severity).toBe("identical-key");
    expect(found[0]!.index).toBe(3);
    expect(found[0]!.entries.map((e) => e.kind).sort()).toEqual(["pgp", "ssh"]);
    expect(found[0]!.message).toContain("SAME private key");
  });

  it("reports a password sharing an index as an entropy prefix", () => {
    const found = findDerivationCollisions(
      vault({
        "5": entry("ssh", "server", { index: 5 }),
        "9": entry("password", "site", { index: 5, length: 16 }),
      }),
    );
    expect(found).toHaveLength(1);
    expect(found[0]!.severity).toBe("entropy-prefix");
    expect(found[0]!.message).toContain("entropy prefix");
  });

  it("orders identical-key collisions ahead of entropy-prefix ones", () => {
    const found = findDerivationCollisions(
      vault({
        "1": entry("ssh", "a", { index: 1 }),
        "2": entry("password", "b", { index: 1, length: 16 }),
        "8": entry("ssh", "c", { index: 8 }),
        "9": entry("pgp", "d", { index: 8 }),
      }),
    );
    // A caller showing only the first line must show the worse one.
    expect(found[0]!.severity).toBe("identical-key");
    expect(found[0]!.index).toBe(8);
  });

  it("uses the vault id as the derivation index when the entry carries none", () => {
    // Password entries derive from their id, not from a stored index field.
    const found = findDerivationCollisions(
      vault({
        "6": entry("password", "from-id", { length: 16 }),
        "7": entry("ssh", "explicit", { index: 6 }),
      }),
    );
    expect(found).toHaveLength(1);
    expect(found[0]!.index).toBe(6);
  });

  it("stays quiet on a vault that cannot collide", () => {
    // What the creation path actually produces: index == id, all distinct.
    expect(
      findDerivationCollisions(
        vault({
          "0": entry("password", "a", { length: 16 }),
          "1": entry("ssh", "b", { index: 1 }),
          "2": entry("pgp", "c", { index: 2 }),
          "3": entry("totp", "d", { index: 3, period: 30, digits: 6 }),
          "4": entry("nostr", "e", { index: 4 }),
        }),
      ),
    ).toEqual([]);
  });

  it("ignores kinds that do not derive from app 32", () => {
    // nostr uses app 39 and seeds derive mnemonics; sharing an index between
    // those and an ssh key is not a collision.
    expect(
      findDerivationCollisions(
        vault({
          "1": entry("ssh", "a", { index: 1 }),
          "2": entry("nostr", "b", { index: 1 }),
          "3": entry("seed", "c", { index: 1, word_count: 12 }),
        }),
      ),
    ).toEqual([]);
  });

  it("does not flag two entries of the same kind at one index", () => {
    // That is a duplicate, which the id rules prevent — not a key-separation
    // failure, and reporting it would train the user to ignore the warning.
    expect(
      findDerivationCollisions(
        vault({
          "1": entry("ssh", "a", { index: 4 }),
          "2": entry("ssh", "b", { index: 4 }),
        }),
      ),
    ).toEqual([]);
  });

  it("still reports an archived entry", () => {
    // Archiving hides an entry from listings; it does not change what the
    // index derives, and the key may already be deployed somewhere.
    const found = findDerivationCollisions(
      vault({
        "1": entry("ssh", "old", { index: 1, archived: true }),
        "2": entry("pgp", "new", { index: 1 }),
      }),
    );
    expect(found).toHaveLength(1);
  });
});
