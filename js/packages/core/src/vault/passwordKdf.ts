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
import { pythonStrip, utf8 } from "../util/bytes.js";
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
  // Python strips a different whitespace set than JS trim(); using trim()
  // here made JS accept passwords Python would reject and derive different
  // keys for others.
  return utf8(pythonStrip(password.normalize("NFKD")));
}

/**
 * Bounds for KDF parameters read from a vault file.
 *
 * The kdf block sits outside the AEAD in the parent-seed wrapper, so anyone
 * who can write the profile directory chooses these numbers. Unbounded, they
 * are a hang or a multi-gigabyte allocation — and this core also runs in a
 * browser tab.
 */
export const KDF_LIMITS = {
  maxTimeCost: 10,
  maxMemoryCost: 1_048_576, // KiB => 1 GiB
  maxParallelism: 16,
  maxIterations: 10_000_000,
} as const;

function boundedParam(value: unknown, fallback: number, max: number, name: string): number {
  const n = value === undefined || value === null ? fallback : Number(value);
  if (!Number.isFinite(n) || !Number.isInteger(n) || n < 1) {
    throw new Error(`KDF parameter ${name} must be a positive integer (got ${String(value)})`);
  }
  if (n > max) {
    throw new Error(
      `KDF parameter ${name} is ${n}, above the maximum ${max}; refusing to run it`,
    );
  }
  return n;
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
    c: boundedParam(iterations, 100_000, KDF_LIMITS.maxIterations, "iterations"),
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
    t: boundedParam(params.time_cost, 2, KDF_LIMITS.maxTimeCost, "time_cost"),
    m: boundedParam(params.memory_cost, 64 * 1024, KDF_LIMITS.maxMemoryCost, "memory_cost"),
    p: boundedParam(params.parallelism, 8, KDF_LIMITS.maxParallelism, "parallelism"),
    dkLen: 32,
  });
  return base64url.encode(key);
}
