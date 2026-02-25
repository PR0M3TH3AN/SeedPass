# SeedPass Secret Handling & Local Exposure Review (Item 3)

Status: `Done`  
Date: `2026-02-25`

## Scope Reviewed

1. `src/seedpass/core/manager.py`
2. `src/utils/fingerprint.py`
3. `src/utils/clipboard.py`
4. `src/utils/memory_protection.py`
5. `src/seedpass/core/portable_backup.py`
6. `src/seedpass/core/backup.py`
7. `src/seedpass/core/encryption.py`

## Exit Criteria Check (Item 3)

1. No secret leakage in logs/temp files/exports by default: `Done`
2. Clipboard, memory lifetime, and file permission checks documented: `Done`

## Findings

### Completed in this pass

1. Removed seed phrase logging from fingerprint generation path.
   - `utils.fingerprint.generate_fingerprint` no longer logs normalized seed/hash.
2. Removed parent-seed plaintext logging from manager setup/save paths.
   - Replaced with non-sensitive debug message.
3. Added regression test for seed phrase log leakage.
   - `src/tests/test_fingerprint_encryption.py::test_generate_fingerprint_does_not_log_seed_phrase`
4. Hardened API upload-import tempfile handling.
   - Server now applies `0o600` permissions on temporary upload files before import.
5. Added API tempfile lifecycle tests.
   - `src/tests/test_api_new_endpoints.py` verifies secure permissions and cleanup on import failure.
6. Redacted BIP85 debug logs that exposed key/entropy-derived material.
   - `local_bip85/bip85.py` now logs only non-sensitive success messages.
7. Added regression test for BIP85 log redaction.
   - `src/tests/test_bip85_derivation_path.py::test_derive_entropy_logs_do_not_expose_key_material`

### Current posture

1. Clipboard helper clears copied values after timeout if unchanged.
   - Covered by `src/tests/test_clipboard_utils.py`.
2. In-memory secret wrapper exists with best-effort wipe semantics.
   - Covered by `src/tests/test_memory_protection.py`.
3. Key encrypted files are written with `0o600` permissions in encryption/backup/export paths.

### Operational notes

1. Default portable database exports are encrypted; plaintext export requires explicit interactive confirmation.
2. Clipboard writes are time-limited and best-effort cleared when unchanged.
3. In-memory secret zeroization remains best-effort due to Python runtime constraints.

## Evidence

1. `src/tests/test_memory_protection.py`
2. `src/tests/test_clipboard_utils.py`
3. `src/tests/test_fingerprint_encryption.py`
4. `src/seedpass/core/manager.py`
5. `src/utils/fingerprint.py`
6. `src/tests/test_api_new_endpoints.py`
7. `src/seedpass/api.py`
8. `src/tests/test_bip85_derivation_path.py`
9. `src/local_bip85/bip85.py`
