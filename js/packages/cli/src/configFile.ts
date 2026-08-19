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
