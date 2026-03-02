# 2026-02-15-relay-health-preflight-job

1. Context
- Users reported intermittent Nostr publish/retrieve failures caused by weak relay availability.
- Existing behavior could fail late in sync flows without a clear preflight decision point.

2. Observation
- Relay health was not always checked before broader sync/release operations.
- Failures were often visible only after publish/retrieve attempts.

3. Action Taken (Runbook Procedure)
- Before sync-sensitive operations, execute relay preflight:
  1. Run relay list review (`seedpass nostr list-relays`).
  2. Ensure at least `MIN_HEALTHY_RELAYS` are expected healthy.
  3. Run a background relay health check path and inspect warnings.
- If healthy relays are below threshold:
  1. Add/rotate relays (`seedpass nostr add-relay <url>`).
  2. Re-run preflight.
  3. Defer broad sync/release operations until threshold is met.

4. Validation Performed
- Confirm relay-health warning path is covered by tests:
  - `src/tests/test_background_relay_check.py`
  - `src/tests/test_background_error_reporting.py`
- Confirm deterministic failure-mode coverage for sync error paths:
  - `src/tests/test_nostr_resilience_failure_modes.py`

5. Recommendation for Next Agents
- Keep relay preflight as a mandatory step in staged rollout checklists.
- If relay health repeatedly degrades, open a dedicated incident note with:
  - failing relay set,
  - retry behavior observed,
  - mitigation actions and final stable relay set.
