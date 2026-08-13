/**
 * Vault payload AEAD, format V3: b"V3|" + nonce(12) + AES-256-GCM
 * ciphertext||tag. Parity target: src/seedpass/core/encryption.py.
 *
 * Uses WebCrypto (globalThis.crypto.subtle), available in Node >= 16 and
 * all target browsers. Legacy V2/Fernet formats are a migration concern
 * handled at a higher layer, not here.
 */

import { concatBytes, utf8 } from "../util/bytes.js";

const V3_PREFIX = utf8("V3|");
const NONCE_LENGTH = 12;

function subtle(): SubtleCrypto {
  const c = globalThis.crypto;
  if (!c?.subtle) throw new Error("WebCrypto (crypto.subtle) is not available");
  return c.subtle;
}

async function importAesKey(key: Uint8Array): Promise<CryptoKey> {
  if (key.length !== 32) throw new Error(`AES-256-GCM key must be 32 bytes, got ${key.length}`);
  return subtle().importKey("raw", key as BufferSource, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

export function isV3Payload(payload: Uint8Array): boolean {
  return (
    payload.length >= V3_PREFIX.length + NONCE_LENGTH &&
    V3_PREFIX.every((b, i) => payload[i] === b)
  );
}

export async function decryptV3(key: Uint8Array, payload: Uint8Array): Promise<Uint8Array> {
  if (!isV3Payload(payload)) throw new Error("not a V3 vault payload");
  const nonce = payload.slice(V3_PREFIX.length, V3_PREFIX.length + NONCE_LENGTH);
  const ciphertext = payload.slice(V3_PREFIX.length + NONCE_LENGTH);
  if (ciphertext.length < 16) throw new Error("AES-GCM payload too short");
  const cryptoKey = await importAesKey(key);
  const plain = await subtle().decrypt(
    { name: "AES-GCM", iv: nonce as BufferSource },
    cryptoKey,
    ciphertext as BufferSource,
  );
  return new Uint8Array(plain);
}

/**
 * Encrypt in V3 format. The nonce parameter exists for fixture tests only;
 * omit it in production use so a fresh random nonce is drawn per call.
 */
export async function encryptV3(
  key: Uint8Array,
  plaintext: Uint8Array,
  nonce?: Uint8Array,
): Promise<Uint8Array> {
  const iv = nonce ?? globalThis.crypto.getRandomValues(new Uint8Array(NONCE_LENGTH));
  if (iv.length !== NONCE_LENGTH) throw new Error(`nonce must be ${NONCE_LENGTH} bytes`);
  const cryptoKey = await importAesKey(key);
  const ciphertext = new Uint8Array(
    await subtle().encrypt({ name: "AES-GCM", iv: iv as BufferSource }, cryptoKey, plaintext as BufferSource),
  );
  return concatBytes(V3_PREFIX, iv, ciphertext);
}
