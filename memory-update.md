# Memory Update (2026-02-25)

## Security Checklist Progress
- Item 6 (`Auth, lock/unlock, and access-control hardening`) moved to `Done`.

## Final Item 6 Hardening Completed
1. Added locked-state API enforcement across protected admin/config/data routes (`423` when locked).
2. Added explicit API unlock endpoint (`POST /api/v1/vault/unlock`).
3. Added dedicated unlock-failure throttling in `seedpass/api.py` (returns `429` after repeated failed unlock attempts).
4. Blocked sensitive config keys in generic config API:
   - `password_hash`
   - `pin_hash`
5. Preserved pre-unlock operational path by keeping fingerprint list/select available while locked.

## Regression Coverage Added
- `test_vault_unlock_endpoint`
- `test_vault_unlock_rate_limited_after_failed_attempts`
- `test_entry_endpoints_blocked_when_vault_locked`
- `test_generate_password_blocked_when_vault_locked`
- `test_config_endpoint_blocked_when_vault_locked`
- `test_get_config_denies_sensitive_keys`
- `test_lock_unlock_cycle_restores_entry_access`

## Validation
- Executed:
  - `src/tests/test_api_new_endpoints.py`
  - `src/tests/test_api.py`
  - `src/tests/test_vault_lock_flag.py`
  - `src/tests/test_inactivity_lock.py`
  - `src/tests/test_unlock_sync.py`
- Result: `66 passed`.

## Next Checklist Candidate
- Item #8 (`Supply chain and release integrity`) is the next major `Not Started` security item.
