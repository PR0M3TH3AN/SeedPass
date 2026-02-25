# Memory Update (2026-02-25)

## Security Checklist Progress
- Item 2 (`Crypto and key management review`) remains `Done`.
- Item 3 (`Secret handling and local data exposure hardening`) moved to `Done`.

## Item 3 Final Hardening Completed
1. Log redaction:
   - Removed seed phrase logging from `utils/fingerprint.py`.
   - Removed parent-seed plaintext debug logging from `seedpass/core/manager.py`.
   - Redacted BIP85 debug logs that previously exposed child-key/entropy-derived material in `local_bip85/bip85.py`.
2. Temp-file hardening:
   - Upload import path in `seedpass/api.py` now enforces `chmod 0o600` before processing.
3. Regression coverage added:
   - `test_generate_fingerprint_does_not_log_seed_phrase`.
   - `test_vault_import_upload_sets_secure_temp_permissions`.
   - `test_vault_import_upload_temp_file_removed_on_failure`.
   - `test_derive_entropy_logs_do_not_expose_key_material`.

## Validation
- Executed:
  - `src/tests/test_bip85_derivation_path.py`
  - `src/tests/test_api_new_endpoints.py`
  - `src/tests/test_fingerprint_encryption.py`
  - `src/tests/test_memory_protection.py`
  - `src/tests/test_clipboard_utils.py`
- Result: `37 passed`.

## Next Checklist Item
- Next highest-priority `Not Started` item is #6: Auth, lock/unlock, and access-control hardening.
