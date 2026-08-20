/**
 * Vault compatibility parity: entry schemas, password KDF, legacy payload
 * formats, and the encrypted-file wrapper. Expected values are
 * Python-generated fixtures.
 */

import { describe, expect, it } from "vitest";
import { base64 } from "@scure/base";
import {
  entriesIndex,
  pbkdf2Cases,
  argon2idCases,
  legacyPayloads,
  mnemonics,
} from "@seedpass/test-vectors";
import {
  parseVaultIndex,
  vaultIndexSchema,
  UnsupportedSchemaVersionError,
  deriveKeyFromPassword,
  deriveKeyFromPasswordArgon2,
  fernetDecrypt,
  FernetError,
  decryptPayload,
  parseEncryptedFile,
  deriveIndexKeyBytes,
} from "@seedpass/core";
import { base64url } from "@scure/base";

const indexKey = () => deriveIndexKeyBytes(mnemonics[legacyPayloads.mnemonic_id]!);

describe("entry schemas (schema_version 4)", () => {
  it("validates the Python-generated index with every entry kind", () => {
    const parsed = parseVaultIndex(entriesIndex.entries);
    const kinds = Object.values(parsed.entries).map((e) => e.kind);
    expect(new Set(kinds)).toEqual(
      new Set([
        "password",
        "totp",
        "ssh",
        "nostr",
        "key_value",
        "document",
        "seed",
        "managed_account",
        "pgp",
      ]),
    );
  });

  it("roundtrips the fixture without altering it", () => {
    const parsed = vaultIndexSchema.parse(entriesIndex.entries);
    expect(JSON.parse(JSON.stringify(parsed))).toEqual(entriesIndex.entries);
  });

  it("refuses future schema versions", () => {
    expect(() => parseVaultIndex({ schema_version: 5, entries: {} })).toThrow(
      UnsupportedSchemaVersionError,
    );
  });

  it("rejects malformed entries", () => {
    const bad = {
      schema_version: 4,
      entries: {
        "0": { type: "password", kind: "password", label: "x", length: 4 },
      },
    };
    expect(() => parseVaultIndex(bad)).toThrow();
  });
});

describe("password KDF", () => {
  it.each(pbkdf2Cases)("pbkdf2 iters=$iterations '$password'", (c) => {
    expect(deriveKeyFromPassword(c.password, c.fingerprint, c.iterations)).toBe(
      c.key_urlsafe_b64,
    );
  });

  it.each(argon2idCases)(
    "argon2id t=$kdf.params.time_cost m=$kdf.params.memory_cost",
    (c) => {
      expect(deriveKeyFromPasswordArgon2(c.password, c.kdf)).toBe(c.key_urlsafe_b64);
    },
  );
});

describe("legacy payload formats", () => {
  // Compare as text, not TypedArray: cross-realm Uint8Array comparison is
  // unreliable under jsdom even when the bytes are identical.
  const text = (b: Uint8Array) => new TextDecoder().decode(b);

  it("decrypts a raw Fernet token", async () => {
    const token = base64.decode(legacyPayloads.fernet_token_b64);
    expect(text(await fernetDecrypt(indexKey(), token))).toBe(legacyPayloads.plaintext_utf8);
    expect(text(await decryptPayload(indexKey(), token))).toBe(legacyPayloads.plaintext_utf8);
  });

  it("decrypts a V2-prefixed AES-GCM payload", async () => {
    const payload = base64.decode(legacyPayloads.v2_gcm_payload_b64);
    expect(text(await decryptPayload(indexKey(), payload))).toBe(legacyPayloads.plaintext_utf8);
  });

  it("decrypts a V2-prefixed Fernet payload via fallback", async () => {
    const payload = base64.decode(legacyPayloads.v2_fernet_payload_b64);
    expect(text(await decryptPayload(indexKey(), payload))).toBe(legacyPayloads.plaintext_utf8);
  });

  it("rejects a Fernet token with a bad HMAC", async () => {
    const token = base64.decode(legacyPayloads.fernet_token_b64);
    const str = new TextDecoder().decode(token);
    const raw = base64url.decode(str);
    raw[raw.length - 1]! ^= 0x01;
    const tampered = base64url.encode(raw);
    await expect(fernetDecrypt(indexKey(), tampered)).rejects.toThrow(FernetError);
  });
});

describe("encrypted file wrapper", () => {
  it("parses the parent-seed wrapper and decrypts with the password key", async () => {
    const spec = legacyPayloads.parent_seed_file;
    const wrapper = base64.decode(spec.wrapper_b64);
    const { kdf, ciphertext } = parseEncryptedFile(wrapper);
    expect(kdf.name).toBe("pbkdf2-sha256");

    const keyB64 = deriveKeyFromPassword(spec.password, spec.fingerprint);
    const key = base64url.decode(keyB64);
    const seed = new TextDecoder().decode(await decryptPayload(key, ciphertext));
    expect(seed).toBe(mnemonics[spec.expected_seed_mnemonic_id]);
  });

  it("falls back to legacy for non-JSON blobs", () => {
    const blob = base64.decode(legacyPayloads.fernet_token_b64);
    const { kdf, ciphertext } = parseEncryptedFile(blob);
    expect(kdf.name).toBe("hkdf");
    expect(ciphertext).toEqual(blob);
  });
});
