# SeedPass Auth, Lock/Unlock & Access-Control Review (Item 6)

Status: `In Progress`  
Date: `2026-02-25`

## Scope Reviewed

1. `src/seedpass/core/manager.py`
2. `src/seedpass/api.py`
3. `src/seedpass/core/api.py`
4. `src/seedpass/core/config_manager.py`

## Exit Criteria Check (Item 6)

1. Lock/unlock/timeout/quick unlock behavior reviewed with tests: `In Progress`

## Findings

### Completed in this pass

1. Added explicit locked-state gate for protected HTTP API routes.
   - Sensitive endpoints now reject access with `423 Vault is locked` when lock flags are set.
2. Added explicit HTTP unlock endpoint.
   - New route: `POST /api/v1/vault/unlock` using `X-SeedPass-Password`.
3. Added API regression tests for lock enforcement and unlock flow.
   - Entry/password endpoints blocked while locked.
   - Unlock endpoint clears locked state path.

### Validation

1. `pytest -q src/tests/test_api_new_endpoints.py src/tests/test_api.py src/tests/test_vault_lock_flag.py src/tests/test_inactivity_lock.py src/tests/test_unlock_sync.py`
2. Result: `62 passed`

### Existing posture

1. Core manager has `lock_vault()` / `unlock_vault()` and publishes lock events.
2. Inactivity timeout enforcement exists via `AuthGuard`.
3. Quick unlock behavior is configurable and covered by existing tests.

### Remaining follow-up

1. Decide whether non-sensitive API routes (config/fingerprint/relays) should also require unlocked state.
2. Add API-level test coverage for timeout-triggered lock then unlock flow.
3. Evaluate rate-limit tuning and brute-force controls for repeated password attempts on unlock endpoints.

## Evidence

1. `src/tests/test_api_new_endpoints.py`
2. `src/tests/test_vault_lock_flag.py`
3. `src/tests/test_inactivity_lock.py`
4. `src/seedpass/api.py`
5. `src/seedpass/core/manager.py`
