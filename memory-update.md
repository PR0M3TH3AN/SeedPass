# Memory Update (2026-02-25)

## Security Checklist Progress
- Item 6 (`Auth, lock/unlock, and access-control hardening`) remains `In Progress` with stronger API-level access control.

## Item 6 Work Completed This Pass
1. Added broader locked-state enforcement in `src/seedpass/api.py`.
   - Protected/admin API routes now return `423` when the vault is locked.
2. Added sensitive config-key protection in API.
   - Generic config API now blocks `password_hash` and `pin_hash` access/updates.
3. Added lock/unlock/access-control regressions in `src/tests/test_api_new_endpoints.py`:
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
- Result: `65 passed`.

## Remaining Item 6 Focus
1. Evaluate whether fingerprint selection/list should be limited while locked in API mode.
2. Add explicit unlock-attempt abuse controls beyond general token rate limiting.
3. Finalize item-6 completion criteria and move to `Done` once remaining policy decisions are resolved.
