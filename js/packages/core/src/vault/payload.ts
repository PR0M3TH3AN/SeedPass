/**
 * Vault payload decryption with legacy fallbacks, mirroring
 * EncryptionManager.decrypt_data, plus the JSON kdf/ct file wrapper from
 * _serialize/_deserialize (src/seedpass/core/encryption.py).
 *
 * Order of attempts, identical to Python:
 *   1. "V3|" prefix  -> AES-256-GCM
 *   2. "V2:" prefix  -> AES-256-GCM; on auth failure, Fernet on the rest
 *   3. otherwise     -> legacy Fernet token
 */

import { base64 } from "@scure/base";
import { decryptV3, isV3Payload } from "./aead.js";
import { fernetDecrypt } from "./fernet.js";
import { kdfConfigSchema, type KdfConfig } from "./passwordKdf.js";
import { utf8 } from "../util/bytes.js";

const V2_PREFIX = utf8("V2:");
const NONCE_LENGTH = 12;

function hasPrefix(payload: Uint8Array, prefix: Uint8Array): boolean {
  return payload.length >= prefix.length && prefix.every((b, i) => payload[i] === b);
}

async function decryptGcmBody(key: Uint8Array, payload: Uint8Array): Promise<Uint8Array> {
  // Reuse the V3 path by re-prefixing the body: both formats are
  // prefix + nonce(12) + ciphertext||tag with the same cipher.
  const body = payload.slice(3);
  if (body.length < NONCE_LENGTH + 16) throw new Error("AES-GCM payload too short");
  const reframed = new Uint8Array(3 + body.length);
  reframed.set(utf8("V3|"), 0);
  reframed.set(body, 3);
  return decryptV3(key, reframed);
}

/** Decrypt any supported vault payload format with `key` (raw 32 bytes). */
export async function decryptPayload(key: Uint8Array, payload: Uint8Array): Promise<Uint8Array> {
  if (isV3Payload(payload)) {
    return decryptV3(key, payload);
  }
  if (hasPrefix(payload, V2_PREFIX)) {
    try {
      return await decryptGcmBody(key, payload);
    } catch {
      // Legacy files sometimes carried a wrong "V2:" header over a Fernet
      // token; Python falls back the same way.
      return fernetDecrypt(key, payload.slice(3));
    }
  }
  return fernetDecrypt(key, payload);
}

export interface EncryptedFile {
  kdf: KdfConfig;
  ciphertext: Uint8Array;
}

/**
 * Parse a stored encrypted file: JSON {"kdf": {...}, "ct": "<b64>"} wrapper,
 * or (legacy) the bare ciphertext with an assumed HKDF config.
 */
export function parseEncryptedFile(blob: Uint8Array): EncryptedFile {
  try {
    const obj = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(blob)) as {
      kdf?: unknown;
      ct?: string;
    };
    if (obj && typeof obj === "object" && typeof obj.ct === "string") {
      const ciphertext = base64.decode(obj.ct);
      if (ciphertext.length > 0) {
        return { kdf: kdfConfigSchema.parse(obj.kdf ?? {}), ciphertext };
      }
    }
  } catch {
    // fall through to legacy
  }
  return {
    kdf: { name: "hkdf", version: 1, params: {}, salt_b64: "" },
    ciphertext: blob,
  };
}
