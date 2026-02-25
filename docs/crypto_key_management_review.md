# SeedPass Crypto & Key Management Review (Item 2)

Status: `In Progress (P0 partially implemented)`  
Date: `2026-02-25`

## Scope Reviewed

1. `src/utils/key_derivation.py`
2. `src/seedpass/core/encryption.py`
3. `src/seedpass/core/vault.py`
4. `src/seedpass/core/portable_backup.py`
5. `src/seedpass/core/manager.py` (unlock/setup key paths)
6. `src/seedpass/core/config_manager.py` (KDF config surface)

## Crypto Inventory (Current)

1. At-rest/index encryption:
   - AES-GCM via `cryptography` (`EncryptionManager.encrypt_data/decrypt_data`).
   - Format marker: `V3|` + 96-bit nonce + ciphertext+tag.
2. Legacy compatibility:
   - Fernet legacy decrypt paths (`V2:` fallback and raw legacy blobs).
3. Password-to-seed key derivation:
   - PBKDF2-HMAC-SHA256 (`derive_key_from_password`) with fingerprint-derived salt.
   - Optional Argon2id path (`derive_key_from_password_argon2`).
4. Seed-to-storage key derivation:
   - deterministic hierarchy from mnemonic seed (`derive_index_key*`).
5. Portable backup encryption:
   - AES-GCM using key derived from parent seed (`derive_index_key`).
6. Integrity checks:
   - Cipher authentication tags (AES-GCM).
   - JSON checksum validation for portable backups.

## Exit Criteria Check (Item 2)

1. Primitive/parameter review completed: `In Progress`
2. Nonce/key lifecycle reviewed: `In Progress`
3. Negative tests for corruption/tampering/wrong key path: `Partially Done`

## Findings

### Strong / Acceptable

1. AES-GCM is used for current encrypted payloads.
2. Migration compatibility from legacy formats is heavily tested.
3. Portable backup import verifies checksum after decrypt.
4. Nostr restore paths include strict error handling and migration fallback.

### Gaps / Risks

1. PBKDF2 default is low for 2026 threat levels:
   - Config default appears to be `50_000` iterations.
   - Legacy fallbacks include `50_000` and `100_000`.
2. Argon2 config drift:
   - `argon2_time_cost` exists in config, but active unlock code constructs
     `KdfConfig(salt_b64=...)` without reading configured `time_cost`.
   - This can create false confidence that tuning is active.
3. AES-GCM nonce reuse guard:
   - Additional guard uses CRC32 of nonce in-memory.
   - CRC32 collision can create false positives under high operation counts.
   - Not persisted across restarts, so not a true global nonce registry.
4. Optional plaintext export mode:
   - `encrypt=False` in portable export intentionally permits plaintext backups.
   - This is a policy risk if used accidentally in production workflows.
5. KDF metadata consistency:
   - File wrapper carries `kdf` metadata, but operational seed-unlock
     parameters are partly config-driven and partly hardcoded/defaulted.
   - Clear authoritative KDF policy per profile is not yet centralized.

## Recommended Remediation Plan

### P0 (Do Next)

1. Wire Argon2 runtime config into active unlock paths:
   - In manager setup/load paths, pass configured `argon2_time_cost` (and any
     agreed memory/parallelism values) into `KdfConfig.params`.
   - Progress: completed in `PasswordManager._derive_seed_key` and wired across
     seed-key callsites; tests added in `src/tests/test_kdf_modes.py`.
2. Raise PBKDF2 default for new profiles:
   - Choose a higher baseline and keep backward compatibility via fallback.
3. Add explicit warnings for plaintext export mode:
   - Keep capability, but require clear confirmation and warning text.

### P1

1. Replace CRC32 nonce tracking with deterministic monotonic counter mode for
   backup/index encryption or remove CRC guard and rely on 96-bit randomness.
2. Define a single profile KDF policy object:
   - Algorithm + parameters + migration behavior in one place.
3. Expand negative tests to include:
   - wrong Argon2 params,
   - tampered kdf metadata wrapper,
   - downgraded KDF policy attempts.

### P2

1. Add release-time crypto policy checks:
   - lint/test gate ensuring configured KDF policy is actually used in unlock paths.

## Test Coverage Snapshot (Relevant)

1. Legacy migration and iteration fallback tests exist.
2. Encryption fuzz and corruption tests exist.
3. Portable backup corruption/checksum tests exist.
4. Additional tests needed for active Argon2 parameter usage in unlock paths.

## Proposed Completion Criteria for Item 2

Item 2 can move to `Done` when:

1. Argon2 config is verifiably wired into unlock path and covered by tests.
2. PBKDF2 policy baseline is explicitly set and documented for new profiles.
3. Plaintext export policy is documented with explicit user safeguards.
4. One nonce-lifecycle decision is implemented (improved guard or rationale for removal).
5. Checklist evidence links are updated to include merged PR/tests.
