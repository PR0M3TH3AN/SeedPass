/**
 * Typed access to the Python-generated parity fixtures.
 *
 * Fixtures are imported as JSON modules (no filesystem access) so the same
 * loader works in Node and browser test environments. Regenerate with:
 *
 *     .venv/bin/python scripts/generate_ts_port_fixtures.py
 */

import manifestJson from "../fixtures/manifest.json";
import bip39Json from "../fixtures/bip39_seeds.json";
import bip85Json from "../fixtures/bip85_entropy.json";
import passwordsV1Json from "../fixtures/passwords_v1.json";
import passwordsV2Json from "../fixtures/passwords_v2.json";
import totpJson from "../fixtures/totp.json";
import nostrKeysJson from "../fixtures/nostr_keys.json";
import managedSeedsJson from "../fixtures/managed_seeds.json";
import fingerprintsJson from "../fixtures/fingerprints.json";
import indexKeysJson from "../fixtures/index_keys.json";
import kdfMetadataJson from "../fixtures/kdf_metadata.json";
import entriesIndexJson from "../fixtures/entries_index.json";
import vaultV3Json from "../fixtures/vault_v3_payload.json";
import passwordKdfJson from "../fixtures/password_kdf.json";
import legacyPayloadsJson from "../fixtures/legacy_payloads.json";

export interface Bip39Case {
  id: string;
  mnemonic: string;
  passphrase: string;
  seed_hex: string;
}

export interface Bip85Case {
  mnemonic_id: string;
  app_no: number;
  index: number;
  entropy_bytes: number;
  word_count: number | null;
  entropy_hex: string;
}

export interface PasswordPolicyParams {
  min_uppercase?: number;
  min_lowercase?: number;
  min_digits?: number;
  min_special?: number;
  include_special_chars?: boolean;
  allowed_special_chars?: string;
  special_mode?: string;
  exclude_ambiguous?: boolean;
}

export interface PasswordCase {
  mnemonic_id: string;
  policy: string;
  policy_params: PasswordPolicyParams;
  length: number;
  index: number;
  password: string;
}

export interface TotpCase {
  mnemonic_id: string;
  index: number;
  secret_b32: string;
  period: number;
  digits: number;
  codes_at: Record<string, string>;
}

export interface NostrKeyCase {
  mnemonic_id: string;
  account_index: number;
  private_key_hex: string;
  public_key_hex: string;
  npub: string;
  nsec: string;
}

export interface ManagedSeedCase {
  mnemonic_id: string;
  words: number;
  index: number;
  child_mnemonic: string;
  child_fingerprint: string;
}

export interface FingerprintCase {
  mnemonic_id: string;
  mnemonic: string;
  fingerprint: string;
}

export interface IndexKeyCase {
  mnemonic_id: string;
  index_key_urlsafe_b64: string;
}

export const manifest = manifestJson as {
  fixture_version: number;
  python_commit: string;
  files: string[];
};

export const mnemonics: Record<string, string> = Object.fromEntries(
  (bip39Json.cases as Bip39Case[]).map((c) => [c.id, c.mnemonic]),
);

export const bip39Cases = bip39Json.cases as Bip39Case[];
export const bip85Cases = bip85Json.cases as Bip85Case[];
export const passwordV1Cases = passwordsV1Json.cases as PasswordCase[];
export const passwordV2Cases = passwordsV2Json.cases as PasswordCase[];
export const totpCases = totpJson.cases as TotpCase[];
export const nostrKeyCases = nostrKeysJson.cases as NostrKeyCase[];
export const managedSeedCases = managedSeedsJson.cases as ManagedSeedCase[];
export const fingerprintCases = fingerprintsJson.cases as FingerprintCase[];
export const indexKeyCases = indexKeysJson.cases as IndexKeyCase[];
export const kdfMetadata = kdfMetadataJson;
export const entriesIndex = entriesIndexJson as {
  fixed_unix: number;
  mnemonic_id: string;
  entries: Record<string, unknown>;
};
export const vaultV3Payload = vaultV3Json as {
  mnemonic_id: string;
  nonce_hex: string;
  payload_b64: string;
  plaintext_sha256: string;
};

export interface Pbkdf2Case {
  password: string;
  fingerprint: string;
  iterations: number;
  key_urlsafe_b64: string;
}

export interface Argon2Case {
  password: string;
  kdf: {
    name: string;
    version: number;
    params: { time_cost: number; memory_cost: number; parallelism: number };
    salt_b64: string;
  };
  key_urlsafe_b64: string;
}

export const pbkdf2Cases = passwordKdfJson.pbkdf2_cases as Pbkdf2Case[];
export const argon2idCases = passwordKdfJson.argon2id_cases as Argon2Case[];

export const legacyPayloads = legacyPayloadsJson as {
  mnemonic_id: string;
  plaintext_utf8: string;
  fernet_token_b64: string;
  v2_gcm_payload_b64: string;
  v2_fernet_payload_b64: string;
  parent_seed_file: {
    password: string;
    fingerprint: string;
    wrapper_b64: string;
    expected_seed_mnemonic_id: string;
  };
};
