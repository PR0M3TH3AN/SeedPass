/**
 * Per-profile encrypted configuration, parity with ConfigManager
 * (seedpass_config.json.enc, encrypted under the index key).
 */

import { readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { decryptPayload, deriveIndexKeyBytes, encryptV3, utf8 } from "@seedpass/core";
import { CONFIG_FILENAME } from "./appDir.js";

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

export async function loadConfig(
  profileDir: string,
  mnemonic: string,
): Promise<Record<string, unknown>> {
  const path = join(profileDir, CONFIG_FILENAME);
  if (!existsSync(path)) return defaultConfig();
  const key = deriveIndexKeyBytes(mnemonic);
  const blob = new Uint8Array(await readFile(path));
  const plain = await decryptPayload(key, blob);
  return { ...defaultConfig(), ...(JSON.parse(new TextDecoder().decode(plain)) as object) };
}

export async function saveConfig(
  profileDir: string,
  mnemonic: string,
  config: Record<string, unknown>,
): Promise<void> {
  const key = deriveIndexKeyBytes(mnemonic);
  const payload = await encryptV3(key, utf8(JSON.stringify(config)));
  await writeFile(join(profileDir, CONFIG_FILENAME), payload, { mode: 0o600 });
}
