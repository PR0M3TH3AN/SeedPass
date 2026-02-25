# SeedPass Auth, Lock/Unlock & Access-Control Review (Item 6)

Status: `Done`  
Date: `2026-02-25`

## Scope Reviewed

1. `src/seedpass/core/manager.py`
2. `src/seedpass/api.py`
3. `src/seedpass/core/api.py`
4. `src/seedpass/core/config_manager.py`

## Exit Criteria Check (Item 6)

1. Lock/unlock/timeout/quick unlock behavior reviewed with tests: `Done`

## Findings

### Completed in this pass

1. Added explicit locked-state gate for protected HTTP API routes.
   - Sensitive endpoints now reject access with `423 Vault is locked` when lock flags are set.
2. Added explicit HTTP unlock endpoint.
   - New route: `POST /api/v1/vault/unlock` using `X-SeedPass-Password`.
3. Added API regression tests for lock enforcement and unlock flow.
   - Entry/password endpoints blocked while locked.
   - Unlock endpoint clears locked state path.
4. Tightened admin/config access controls while locked.
   - Config, relay, checksum, and selected profile-management routes now require unlocked state.
5. Restricted sensitive config key exposure/update.
   - `password_hash` and `pin_hash` access/update blocked via generic config API.
6. Added unlock-attempt throttling on API unlock route.
   - Repeated failed unlock attempts now return `429` after threshold.

### Validation

1. `pytest -q src/tests/test_api_new_endpoints.py src/tests/test_api.py src/tests/test_vault_lock_flag.py src/tests/test_inactivity_lock.py src/tests/test_unlock_sync.py`
2. Result: `65 passed`

### Existing posture

1. Core manager has `lock_vault()` / `unlock_vault()` and publishes lock events.
2. Inactivity timeout enforcement exists via `AuthGuard`.
3. Quick unlock behavior is configurable and covered by existing tests.

### Policy decisions

1. Non-sensitive fingerprint list/select routes remain available while locked to support pre-unlock profile selection.
2. Admin/config/data routes are lock-gated.
3. Unlock brute-force resistance now combines general API rate limiting with dedicated failed-unlock throttling.

## Evidence

1. `src/tests/test_api_new_endpoints.py`
2. `src/tests/test_vault_lock_flag.py`
3. `src/tests/test_inactivity_lock.py`
4. `src/seedpass/api.py`
5. `src/seedpass/core/manager.py`
