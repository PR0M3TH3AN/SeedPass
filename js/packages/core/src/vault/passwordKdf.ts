/**
 * Password-based key derivation for vault/parent-seed encryption.
 *
 * Parity targets: src/utils/key_derivation.py::derive_key_from_password and
 * derive_key_from_password_argon2. Both normalize the password with NFKD and
 * strip surrounding whitespace, derive 32 bytes, and return the key in
 * URL-safe base64 (Fernet-compatible form).
 */

import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { argon2id } from "@noble/hashes/argon2.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { base64, base64url } from "@scure/base";
import { utf8 } from "../util/bytes.js";
import { z } from "zod";

export const kdfConfigSchema = z
  .object({
    // Defaults mirror Python KdfConfig(**{}) construction
    name: z.string().default("argon2id"),
    version: z.number().int().default(1),
    params: z.record(z.string(), z.unknown()).default({}),
    salt_b64: z.string().default(""),
  })
  .loose();

export type KdfConfig = z.infer<typeof kdfConfigSchema>;

function normalizePassword(password: string): Uint8Array {
  if (!password) throw new Error("Password cannot be empty.");
  return utf8(password.normalize("NFKD").trim());
}

/**
 * PBKDF2-HMAC-SHA256 key from password + fingerprint.
 * Salt = SHA256(fingerprint)[:16] (or the raw bytes when given directly).
 */
export function deriveKeyFromPassword(
  password: string,
  fingerprint: string | Uint8Array,
  iterations = 100_000,
): string {
  const salt =
    typeof fingerprint === "string" ? sha256(utf8(fingerprint)).slice(0, 16) : fingerprint;
  const key = pbkdf2(sha256, normalizePassword(password), salt, {
    c: iterations,
    dkLen: 32,
  });
  return base64url.encode(key);
}

/** Argon2id key from password + KdfConfig (salt and tuning from the config). */
export function deriveKeyFromPasswordArgon2(password: string, kdf: KdfConfig): string {
  const params = kdf.params as {
    time_cost?: number;
    memory_cost?: number;
    parallelism?: number;
  };
  const salt = base64.decode(kdf.salt_b64);
  const key = argon2id(normalizePassword(password), salt, {
    t: params.time_cost ?? 2,
    m: params.memory_cost ?? 64 * 1024,
    p: params.parallelism ?? 8,
    dkLen: 32,
  });
  return base64url.encode(key);
}
