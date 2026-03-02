# TUI v2 Cutover Decision Memo

Date: March 2, 2026  
Branch: `beta`  
Decision owner: SeedPass maintainers

## Decision

Current branch state: `seedpass` default interactive routing launches TUI v2 first.  
Legacy fallback remains intentionally available during hardening:
- `seedpass --legacy-tui`
- `seedpass legacy`
- `seedpass tui2 --fallback-legacy`

## Decision Update (March 2, 2026)

Cutover readiness has improved materially since the initial memo draft:
- parity checklist now marks full legacy workflow coverage complete
- Textual interaction suites and parity matrix coverage are in place
- CI now includes both runtime smoke and stronger coverage gates for TUI v2 critical paths
- deterministic Nostr failure-mode resilience tests have been expanded

Given this state, the default routing decision on `beta` is now technically aligned with implemented gates. Remaining work is focused on release hardening and operational risk controls, not core TUI parity.

## Gate Status Snapshot

1. Parity closure: **Pass**
- `docs/tui_v2_parity_checklist.md` marks `Full legacy workflow coverage: Yes`.
- Evidence:
  - `artifacts/agent_tui_test/20260302T135526Z/report.json`
  - `artifacts/agent_tui2_test/20260302T135526Z/report.json`

2. Test coverage and CI gates: **Pass (expanded)**
- Runtime smoke:
  - `scripts/tui2_check_smoke.sh`
- Critical module gate (default in CI runner):
  - `scripts/check_critical_coverage.py`
  - includes `src/seedpass/core/api.py >= 85%`
- Focused TUI v2 gate:
  - `scripts/tui2_coverage_gate.sh`
  - enforces:
    - `src/seedpass/tui_v2/app.py >= 78%`
    - `src/seedpass/core/api.py >= 85%`

3. Large-vault validation: **Pass**
- `src/tests/test_tui_v2_large_vault_validation.py`
- `src/tests/test_tui_v2_kb_scale_stress.py`

4. Docs/help alignment: **Pass (ongoing maintenance)**
- keybinding/palette help updated with landed parity commands
- cutover/fallback command paths documented in parity/checklist docs

5. Release safety fallback: **Pass**
- legacy fallback command/flag paths retained for one-release safety window

## Remaining Blockers (Cutover Hardening)

These are now the main blockers for promoting from `beta` hardening to broad release confidence:

1. Nostr resilience soak validation (beyond deterministic unit tests)
- deterministic failure-mode suite now exists:
  - `src/tests/test_nostr_resilience_failure_modes.py`
- still recommended:
  - optional real-relay soak lane and outage/retry drift capture across environments

2. Supply-chain and release-integrity completion
- complete pending items in `docs/supply_chain_release_integrity.md`:
  - release-protection enforcement
  - GHSA exception disposition documentation
  - maintainer verification runbook evidence

3. Operational runbooks and staged rollout evidence
- incident/runbook readiness still open in `docs/security_readiness_checklist.md`
- staged rollout + rollback drill evidence still needs explicit record

## Rollout Recommendation

For the next production-facing release:
1. Keep TUI v2 default route.
2. Keep legacy fallback enabled for one release.
3. Publish release notes with explicit fallback instructions.
4. Require passing:
   - `scripts/run_ci_tests.sh`
   - `scripts/tui2_coverage_gate.sh`
   - parity bug-bash harnesses (`ai_tui_agent_test.py`, `ai_tui2_agent_test.py`)

## Rollback Plan

If a cutover regression is detected:
- switch default interactive route back to legacy TUI in CLI callback routing
- keep TUI v2 as opt-in path while patching regressions
- publish incident note with repro, mitigation, and re-enable criteria
