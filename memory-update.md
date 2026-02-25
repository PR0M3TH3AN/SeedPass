# Memory Update (2026-02-25)

## Security Checklist Progress
- Item 6 (`Auth, lock/unlock, and access-control hardening`) moved from `Not Started` to `In Progress`.
- Added evidence links in `docs/security_readiness_checklist.md` and created a dedicated review doc.

## Item 6 Work Completed This Pass
1. Added locked-state access control for protected HTTP API routes in `src/seedpass/api.py`.
   - Protected routes now return `423` with `"Vault is locked"` when lock flags are active.
2. Added explicit HTTP unlock route:
   - `POST /api/v1/vault/unlock` using `X-SeedPass-Password`.
3. Added auth/access regression tests in `src/tests/test_api_new_endpoints.py`:
   - `test_vault_unlock_endpoint`
   - `test_entry_endpoints_blocked_when_vault_locked`
   - `test_generate_password_blocked_when_vault_locked`

## Validation
- Executed:
  - `src/tests/test_api_new_endpoints.py`
  - `src/tests/test_api.py`
  - `src/tests/test_vault_lock_flag.py`
  - `src/tests/test_inactivity_lock.py`
  - `src/tests/test_unlock_sync.py`
- Result: `62 passed`.

## Next Item 6 Steps
1. Decide whether non-sensitive API routes (config/fingerprint/relays) should also require unlocked state.
2. Add timeout-to-lock to unlock route E2E test path.
3. Evaluate brute-force resistance/rate-limit behavior specific to unlock attempts.
