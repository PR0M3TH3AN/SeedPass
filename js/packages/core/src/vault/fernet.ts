/**
 * Fernet token decryption (legacy vault format, migration only).
 *
 * Spec: https://github.com/fernet/spec — version 0x80, AES-128-CBC with
 * PKCS7 padding, HMAC-SHA256 over version||timestamp||iv||ciphertext.
 * The 32-byte key splits into signing key (first 16) and encryption key
 * (last 16). TTL checking is not implemented — SeedPass never sets one.
 *
 * Vault data is always written as V3 AES-GCM, never Fernet. The one exception
 * is the high-risk partition and its key envelope: those files are read and
 * written by BOTH implementations, and Python's format is Fernet, so writing
 * them requires an encryptor. Do not reach for it for anything else — a new
 * Fernet payload anywhere in the vault is a bug.
 */

import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { base64url } from "@scure/base";

const VERSION = 0x80;
const HEADER_LENGTH = 1 + 8 + 16; // version + timestamp + IV
const HMAC_LENGTH = 32;

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

export class FernetError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FernetError";
  }
}

async function aesCbcDecrypt(
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await globalThis.crypto.subtle.importKey(
    "raw",
    key as BufferSource,
    { name: "AES-CBC" },
    false,
    ["decrypt"],
  );
  const plain = await globalThis.crypto.subtle.decrypt(
    { name: "AES-CBC", iv: iv as BufferSource },
    cryptoKey,
    ciphertext as BufferSource,
  );
  return new Uint8Array(plain);
}

/**
 * Decrypt a Fernet token. `token` is the base64url token as stored on disk
 * (either the ASCII bytes or the decoded string); `key` is the raw 32 bytes.
 */
export async function fernetDecrypt(
  key: Uint8Array,
  token: Uint8Array | string,
): Promise<Uint8Array> {
  if (key.length !== 32) throw new FernetError("Fernet key must be 32 bytes");
  const tokenStr = typeof token === "string" ? token : new TextDecoder().decode(token);
  let raw: Uint8Array;
  try {
    raw = base64url.decode(tokenStr.trim());
  } catch {
    throw new FernetError("invalid token encoding");
  }
  if (raw.length < HEADER_LENGTH + HMAC_LENGTH || raw[0] !== VERSION) {
    throw new FernetError("invalid token structure");
  }

  const signed = raw.slice(0, raw.length - HMAC_LENGTH);
  const tag = raw.slice(raw.length - HMAC_LENGTH);
  const expected = hmac(sha256, key.slice(0, 16), signed);
  if (!constantTimeEqual(tag, expected)) {
    throw new FernetError("invalid token HMAC");
  }

  const iv = raw.slice(1 + 8, HEADER_LENGTH);
  const ciphertext = raw.slice(HEADER_LENGTH, raw.length - HMAC_LENGTH);
  if (ciphertext.length === 0 || ciphertext.length % 16 !== 0) {
    throw new FernetError("invalid ciphertext length");
  }
  try {
    return await aesCbcDecrypt(key.slice(16, 32), iv, ciphertext);
  } catch {
    throw new FernetError("decryption failed");
  }
}

async function aesCbcEncrypt(
  key: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await globalThis.crypto.subtle.importKey(
    "raw",
    key as BufferSource,
    { name: "AES-CBC" },
    false,
    ["encrypt"],
  );
  // WebCrypto applies PKCS7 padding itself, which is what Fernet specifies.
  const out = await globalThis.crypto.subtle.encrypt(
    { name: "AES-CBC", iv: iv as BufferSource },
    cryptoKey,
    plaintext as BufferSource,
  );
  return new Uint8Array(out);
}

/**
 * Produce a Fernet token, for the two files Python also writes.
 *
 * `key` is the raw 32 bytes: signing key first 16, encryption key last 16.
 * `iv` and `timestamp` exist for tests that need a fixed token; production
 * must let both default, since a repeated IV under one key breaks CBC.
 */
export async function fernetEncrypt(
  key: Uint8Array,
  plaintext: Uint8Array,
  options: { iv?: Uint8Array; timestamp?: number } = {},
): Promise<string> {
  if (key.length !== 32) throw new FernetError(`Fernet key must be 32 bytes, got ${key.length}`);
  const signingKey = key.slice(0, 16);
  const encryptionKey = key.slice(16);
  const iv = options.iv ?? globalThis.crypto.getRandomValues(new Uint8Array(16));
  if (iv.length !== 16) throw new FernetError("Fernet IV must be 16 bytes");
  const timestamp = BigInt(options.timestamp ?? Math.floor(Date.now() / 1000));

  const ciphertext = await aesCbcEncrypt(encryptionKey, iv, plaintext);
  const body = new Uint8Array(HEADER_LENGTH + ciphertext.length);
  body[0] = VERSION;
  // Big-endian 64-bit seconds, as the spec has it.
  for (let i = 0; i < 8; i++) {
    body[1 + i] = Number((timestamp >> BigInt(8 * (7 - i))) & 0xffn);
  }
  body.set(iv, 9);
  body.set(ciphertext, HEADER_LENGTH);

  const tag = hmac(sha256, signingKey, body);
  const token = new Uint8Array(body.length + HMAC_LENGTH);
  token.set(body);
  token.set(tag, body.length);
  return base64url.encode(token);
}
