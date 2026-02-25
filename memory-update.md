# Memory Update (2026-02-25)

## Security Item 2 Progress
- Raised PBKDF2 default policy for new profiles from `50_000` to `200_000` via `ConfigManager.DEFAULT_PBKDF2_ITERATIONS`.
- Added policy-floor enforcement in `PasswordManager._get_kdf_iterations()` so downgraded configured values are ignored during normal seed-key derivation.
- Kept unlock backward compatibility for legacy profiles by preserving fallback attempts for `50_000` and `100_000` iterations.

## KDF Metadata Consistency
- Added `PasswordManager._build_seed_kdf_config(...)` and wired all seed re-encryption callsites to persist explicit KDF metadata (`pbkdf2` or `argon2id`) matching active derivation policy.

## Plaintext Export Safeguard
- Hardened `handle_export_database` interactive flow: plaintext export now requires explicit warning + second confirmation.
- Added audit metadata for backup exports (`encryption_mode` field).

## Nonce Lifecycle Decision
- Removed CRC32 nonce tracking from `EncryptionManager.encrypt_data`.
- Policy now relies on fresh random 96-bit AES-GCM nonces per encryption call to avoid CRC false positives and in-memory collision bookkeeping.

## Added/Updated Tests
- Expanded `src/tests/test_kdf_modes.py` with negatives for:
  - wrong Argon2 params on unlock,
  - tampered KDF wrapper payload,
  - downgraded KDF policy attempt (floor enforcement).
- Added `src/tests/test_export_plaintext_policy.py` for double-confirm plaintext export guard.
- Updated expectations in `test_config_manager.py` and `test_kdf_strength_slider.py` for new PBKDF2 baseline.

## Validation
- Ran targeted suite:
  - `src/tests/test_kdf_modes.py`
  - `src/tests/test_export_plaintext_policy.py`
  - `src/tests/test_config_manager.py`
  - `src/tests/test_kdf_strength_slider.py`
  - `src/tests/test_noninteractive_init_unlock.py`
  - `src/tests/test_password_unlock_after_change.py`
- Result: `28 passed`.
