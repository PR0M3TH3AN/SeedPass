/**
 * Python/TypeScript parity tests. Every expected value comes from
 * Python-generated fixtures in @seedpass/test-vectors; a failure here means
 * the port diverges from the reference implementation.
 */

import { describe, expect, it } from "vitest";
import { mnemonicToSeedSync } from "@scure/bip39";
import {
  bip39Cases,
  bip85Cases,
  passwordV1Cases,
  passwordV2Cases,
  totpCases,
  nostrKeyCases,
  managedSeedCases,
  fingerprintCases,
  indexKeyCases,
  entriesIndex,
  vaultV3Payload,
  mnemonics,
  type PasswordCase,
} from "@seedpass/test-vectors";
import { sha256 } from "@noble/hashes/sha2.js";
import { base64 } from "@scure/base";
import {
  Bip85,
  generatePassword,
  deriveTotpSecret,
  totpCodeAt,
  deriveNostrKeys,
  generateFingerprint,
  deriveIndexKey,
  deriveIndexKeyBytes,
  decryptV3,
  bytesToHex,
  type PasswordPolicy,
} from "@seedpass/core";

function bip85For(mnemonicId: string): Bip85 {
  const mnemonic = mnemonics[mnemonicId];
  if (!mnemonic) throw new Error(`unknown mnemonic id ${mnemonicId}`);
  return Bip85.fromMnemonic(mnemonic);
}

function toPolicy(c: PasswordCase): PasswordPolicy {
  const p = c.policy_params;
  return {
    ...(p.min_uppercase !== undefined && { minUppercase: p.min_uppercase }),
    ...(p.min_lowercase !== undefined && { minLowercase: p.min_lowercase }),
    ...(p.min_digits !== undefined && { minDigits: p.min_digits }),
    ...(p.min_special !== undefined && { minSpecial: p.min_special }),
    ...(p.include_special_chars !== undefined && {
      includeSpecialChars: p.include_special_chars,
    }),
    ...(p.allowed_special_chars !== undefined && {
      allowedSpecialChars: p.allowed_special_chars,
    }),
    ...(p.special_mode !== undefined && { specialMode: p.special_mode }),
    ...(p.exclude_ambiguous !== undefined && { excludeAmbiguous: p.exclude_ambiguous }),
  };
}

describe("BIP-39 seed", () => {
  it.each(bip39Cases)("$id", (c) => {
    expect(bytesToHex(mnemonicToSeedSync(c.mnemonic, c.passphrase))).toBe(c.seed_hex);
  });
});

describe("BIP-85 entropy", () => {
  it.each(bip85Cases)(
    "$mnemonic_id app=$app_no index=$index bytes=$entropy_bytes",
    (c) => {
      const entropy = bip85For(c.mnemonic_id).deriveEntropy({
        index: c.index,
        entropyBytes: c.entropy_bytes,
        appNo: c.app_no,
        ...(c.word_count !== null && { wordCount: c.word_count }),
      });
      expect(bytesToHex(entropy)).toBe(c.entropy_hex);
    },
  );
});

describe("password derivation v1 (frozen)", () => {
  it.each(passwordV1Cases)("$policy len=$length idx=$index", (c) => {
    const password = generatePassword(bip85For(c.mnemonic_id), {
      length: c.length,
      index: c.index,
      genVersion: 1,
      policy: toPolicy(c),
    });
    expect(password).toBe(c.password);
  });
});

describe("password derivation v2", () => {
  it.each(passwordV2Cases)("$policy len=$length idx=$index", (c) => {
    const password = generatePassword(bip85For(c.mnemonic_id), {
      length: c.length,
      index: c.index,
      genVersion: 2,
      policy: toPolicy(c),
    });
    expect(password).toBe(c.password);
  });
});

describe("TOTP", () => {
  it.each(totpCases)("$mnemonic_id idx=$index", (c) => {
    const mnemonic = mnemonics[c.mnemonic_id]!;
    expect(deriveTotpSecret(mnemonic, c.index)).toBe(c.secret_b32);
    for (const [ts, code] of Object.entries(c.codes_at)) {
      expect(totpCodeAt(c.secret_b32, Number(ts), c.period, c.digits)).toBe(code);
    }
  });
});

describe("Nostr keys", () => {
  it.each(nostrKeyCases)("$mnemonic_id idx=$account_index", (c) => {
    const keys = deriveNostrKeys(bip85For(c.mnemonic_id), c.account_index);
    expect(keys.privateKeyHex).toBe(c.private_key_hex);
    expect(keys.publicKeyHex).toBe(c.public_key_hex);
    expect(keys.npub).toBe(c.npub);
    expect(keys.nsec).toBe(c.nsec);
  });
});

describe("managed seeds (BIP-85 child mnemonics)", () => {
  it.each(managedSeedCases)("$mnemonic_id words=$words idx=$index", (c) => {
    const child = bip85For(c.mnemonic_id).deriveMnemonic(c.index, c.words as 12 | 18 | 24);
    expect(child).toBe(c.child_mnemonic);
    expect(generateFingerprint(child)).toBe(c.child_fingerprint);
  });
});

describe("fingerprints", () => {
  it.each(fingerprintCases)("$mnemonic_id", (c) => {
    expect(generateFingerprint(c.mnemonic)).toBe(c.fingerprint);
  });
});

describe("vault index key", () => {
  it.each(indexKeyCases)("$mnemonic_id", (c) => {
    expect(deriveIndexKey(mnemonics[c.mnemonic_id]!)).toBe(c.index_key_urlsafe_b64);
  });
});

describe("vault V3 payload", () => {
  it("decrypts the Python-encrypted fixture", async () => {
    const key = deriveIndexKeyBytes(mnemonics[vaultV3Payload.mnemonic_id]!);
    const payload = base64.decode(vaultV3Payload.payload_b64);
    const plaintext = await decryptV3(key, payload);
    expect(bytesToHex(sha256(plaintext))).toBe(vaultV3Payload.plaintext_sha256);

    const parsed = JSON.parse(new TextDecoder().decode(plaintext)) as Record<string, unknown>;
    expect(Object.keys(parsed).sort()).toEqual(Object.keys(entriesIndex.entries).sort());
  });

  it("rejects tampered ciphertext", async () => {
    const key = deriveIndexKeyBytes(mnemonics[vaultV3Payload.mnemonic_id]!);
    const payload = base64.decode(vaultV3Payload.payload_b64);
    payload[payload.length - 1]! ^= 0x01;
    await expect(decryptV3(key, payload)).rejects.toThrow();
  });
});
