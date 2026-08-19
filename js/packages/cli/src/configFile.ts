/**
 * Per-profile encrypted configuration, parity with ConfigManager
 * (seedpass_config.json.enc, encrypted under the index key).
 */

import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import {
  decryptPayload,
  deriveIndexKeyBytes,
  encryptV3,
  parseEncryptedFile,
  passwordPolicyFromRecord,
  utf8,
  type PasswordPolicy,
} from "@seedpass/core";
import { CONFIG_FILENAME } from "./appDir.js";
import { atomicWrite, withVaultLock } from "./vaultFile.js";

export const DEFAULT_RELAYS = [
  "wss://relay.snort.social",
  "wss://nostr.oxtr.dev",
  "wss://relay.primal.net",
];

/** Defaults mirror ConfigManager.load_config. */
export function defaultConfig(): Record<string, unknown> {
  return {
    relays: [...DEFAULT_RELAYS],
    offline_mode: false,
    online_mode_notice_seen: false,
    pin_hash: "",
    password_hash: "",
    inactivity_timeout: 900,
    kdf_iterations: 200000,
    kdf_mode: "pbkdf2",
    argon2_time_cost: 2,
    additional_backup_path: "",
    backup_interval: 0,
    secret_mode_enabled: false,
    clipboard_clear_delay: 45,
    quick_unlock_enabled: false,
    nostr_max_retries: 2,
    nostr_retry_delay: 1.0,
    min_uppercase: 2,
    min_lowercase: 2,
    min_digits: 2,
    min_special: 2,
  };
}

/**
 * Config keys a caller may set through the API, and how each value is
 * normalized.
 *
 * WHY AN ALLOWLIST
 *
 * `PUT /api/v1/config/:key` took the key straight from the URL and the value
 * straight from the body, so any string at all became a permanent config
 * entry holding any JSON at all. A typo (`inactivity_timout`) was accepted,
 * stored forever, and reported as ok while the setting it was meant to
 * change never moved. Nothing downstream ever reads an unknown key, so the
 * failure is silent by construction.
 *
 * Python allowlists too (`api.py`, update_config) but its list is much
 * narrower — it cannot set the password-policy keys at all, which this
 * implementation can and does. So this is a superset of Python's rather than
 * a copy of it: matching Python exactly would mean deleting working
 * behaviour to reproduce a limitation. The divergence is recorded in TODO.md.
 *
 * Coercion matters as much as the allowlist. `inactivity_timeout: "soon"`
 * used to be stored verbatim and produce NaN comparisons at lock time; the
 * normalizer rejects it instead. Python does `float(v)`, which raises
 * uncaught and answers 500 — a 400 is the same refusal, said properly.
 */
export class ConfigValueError extends Error {}

function asNumber(key: string, v: unknown): number {
  const n = Number(v);
  if (typeof v === "boolean" || v === null || v === "" || !Number.isFinite(n)) {
    throw new ConfigValueError(`${key} must be a number`);
  }
  return n;
}

function asInt(key: string, v: unknown): number {
  return Math.trunc(asNumber(key, v));
}

function asNonNegativeInt(key: string, v: unknown): number {
  const n = asInt(key, v);
  if (n < 0) throw new ConfigValueError(`${key} must not be negative`);
  return n;
}

function asString(key: string, v: unknown): string {
  if (typeof v !== "string") throw new ConfigValueError(`${key} must be a string`);
  return v;
}

function asStringArray(key: string, v: unknown): string[] {
  if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) {
    throw new ConfigValueError(`${key} must be an array of strings`);
  }
  return v as string[];
}

export const SETTABLE_CONFIG_KEYS: Record<string, (v: unknown) => unknown> = {
  relays: (v) => {
    const list = asStringArray("relays", v);
    // An empty relay list is not a configuration, it is an outage: sync
    // would silently stop with everything still reporting healthy.
    if (list.length === 0) throw new ConfigValueError("relays must not be empty");
    return list;
  },
  offline_mode: (v) => Boolean(v),
  online_mode_notice_seen: (v) => Boolean(v),
  inactivity_timeout: (v) => {
    const n = asNumber("inactivity_timeout", v);
    // Zero would mean "lock immediately", which is indistinguishable from a
    // broken vault, and negative means "already expired".
    if (n <= 0) throw new ConfigValueError("inactivity_timeout must be positive");
    return n;
  },
  kdf_iterations: (v) => {
    const n = asInt("kdf_iterations", v);
    if (n < 1) throw new ConfigValueError("kdf_iterations must be at least 1");
    return n;
  },
  kdf_mode: (v) => asString("kdf_mode", v),
  argon2_time_cost: (v) => asNonNegativeInt("argon2_time_cost", v),
  additional_backup_path: (v) => asString("additional_backup_path", v),
  backup_interval: (v) => asNonNegativeInt("backup_interval", v),
  secret_mode_enabled: (v) => Boolean(v),
  clipboard_clear_delay: (v) => asNonNegativeInt("clipboard_clear_delay", v),
  quick_unlock_enabled: (v) => Boolean(v),
  nostr_max_retries: (v) => asNonNegativeInt("nostr_max_retries", v),
  nostr_retry_delay: (v) => asNumber("nostr_retry_delay", v),
  nostr_key_index: (v) => asNonNegativeInt("nostr_key_index", v),
  // Password policy. Absent from Python's API allowlist; see above.
  include_special_chars: (v) => Boolean(v),
  allowed_special_chars: (v) => asString("allowed_special_chars", v),
  special_mode: (v) => asString("special_mode", v),
  exclude_ambiguous: (v) => Boolean(v),
  min_uppercase: (v) => asNonNegativeInt("min_uppercase", v),
  min_lowercase: (v) => asNonNegativeInt("min_lowercase", v),
  min_digits: (v) => asNonNegativeInt("min_digits", v),
  min_special: (v) => asNonNegativeInt("min_special", v),
};

/**
 * Credential verifiers. Offline-crackable, and nothing legitimate reads them
 * over the wire or writes them through a generic setter.
 */
export const SENSITIVE_CONFIG_KEYS = new Set(["password_hash", "pin_hash"]);

/**
 * The profile's password policy, as the BASE that entry `policy` blocks
 * override.
 *
 * Parity with ConfigManager.get_password_policy: the config keys carry the
 * same snake_case names as an entry's policy block, so the entry parser reads
 * both. Keys absent from the config stay absent here rather than being
 * materialized as defaults — that is what lets an entry override exactly the
 * fields it names and inherit the rest, matching Python's
 * `dataclasses.replace(base, **overrides)`.
 */
export function passwordPolicyFromConfig(
  config: Record<string, unknown>,
): PasswordPolicy {
  return passwordPolicyFromRecord(config);
}

export async function loadConfig(
  profileDir: string,
  mnemonic: string,
): Promise<Record<string, unknown>> {
  const path = join(profileDir, CONFIG_FILENAME);
  if (!existsSync(path)) return defaultConfig();
  const key = deriveIndexKeyBytes(mnemonic);
  const blob = new Uint8Array(await readFile(path));
  // Python writes config through EncryptionManager.save_json_data, which
  // wraps the ciphertext in a kdf/ct JSON envelope; TS writes it bare.
  // parseEncryptedFile handles both.
  const plain = await decryptPayload(key, parseEncryptedFile(blob).ciphertext);
  return { ...defaultConfig(), ...(JSON.parse(new TextDecoder().decode(plain)) as object) };
}

export async function saveConfig(
  profileDir: string,
  mnemonic: string,
  config: Record<string, unknown>,
): Promise<void> {
  const path = join(profileDir, CONFIG_FILENAME);
  await withVaultLock(path, async () => {
    const key = deriveIndexKeyBytes(mnemonic);
    const payload = await encryptV3(key, utf8(JSON.stringify(config)));
    await atomicWrite(path, payload);
  });
}

/**
 * Read, modify and write the config under one lock.
 *
 * `config set`, `nostr add-relay` and `nostr remove-relay` are all
 * read-modify-write cycles. Locking only the write loses concurrent updates
 * — the config holds the relay list and password/pin hashes, so a lost
 * update there is not cosmetic.
 */
export async function mutateConfig<T>(
  profileDir: string,
  mnemonic: string,
  fn: (config: Record<string, unknown>) => T | Promise<T>,
): Promise<T> {
  const path = join(profileDir, CONFIG_FILENAME);
  return withVaultLock(path, async () => {
    const config = await loadConfig(profileDir, mnemonic);
    const result = await fn(config);
    const key = deriveIndexKeyBytes(mnemonic);
    await atomicWrite(path, await encryptV3(key, utf8(JSON.stringify(config))));
    return result;
  });
}
