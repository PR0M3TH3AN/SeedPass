# SeedPass Dev Control Center

Last updated: 2026-03-02  
Branch baseline: `beta`

This is the single source-of-truth document to decide what to work on next.

## 1) Current Health Gate

Run before starting any new slice:

```bash
git pull --rebase origin beta
PATH=".venv/bin:$PATH" scripts/run_ci_tests.sh
```

Latest verification in this session:
- `origin/beta` matched local `beta` (no new remote commits to pull).
- `scripts/run_ci_tests.sh`: PASS
  - determinism gate: PASS
  - full suite: `979 passed, 16 skipped`
  - coverage: `85.65%`
- Focused TUI validation slices:
  - `poetry run pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py`
  - latest result: `31 passed`
  - includes profile-tree keyboard navigation/select command coverage

## 2) Canonical Status Sources

Use these docs as inputs, but treat this file as the decision layer:

- TUI v2 plan: `docs/tui_v2_plan.md`
- TUI parity backlog: `docs/tui_v2_parity_backlog.md`
- TUI parity checklist: `docs/tui_v2_parity_checklist.md`
- TUI legacy parity matrix: `docs/tui_v2_legacy_parity_matrix.md`
- TUI v2 UI refresh plan (mockup-aligned): `docs/tui_v2_ui_refresh_plan.md`
- Semantic vector index integration plan: `docs/semantic_vector_index_plan.md`
- Cutover memo: `docs/tui_v2_cutover_decision.md`
- Security readiness: `docs/security_readiness_checklist.md`
- Supply-chain integrity: `docs/supply_chain_release_integrity.md`
- QA roadmap: `docs/agent_testing_roadmap.md`
- Agent TUI testing: `docs/ai_agent_tui_testing.md`
- KB scale validation: `docs/kb_scale_validation.md`
- Beta hardening report: `docs/beta_hardening_2026-03-02.md`

## 3) What Is Still Open

### Parity / Product
- TUI v2 legacy parity closure is now documented as complete:
  - `docs/tui_v2_parity_checklist.md` (“Full legacy workflow coverage: Yes”)
  - bug-bash evidence reports:
    - `artifacts/agent_tui_test/20260302T135526Z/report.json`
    - `artifacts/agent_tui2_test/20260302T135526Z/report.json`

### Security Readiness
- `docs/security_readiness_checklist.md` still marks:
  - #4 Backup/restore integrity: **In Progress**
  - #5 Nostr sync security/resilience: **In Progress**
  - #7 Testing gates/quality thresholds: **In Progress**
  - #8 Supply chain/release integrity: **In Progress**
  - #9 Operational runbooks: **In Progress**
  - #10 External audit/rollout: **In Progress**

### Supply Chain Specific
- `docs/supply_chain_release_integrity.md` remaining work:
  - execute at least one tagged production release through integrity workflow and record evidence
  - resolve or renew exception `GHSA-wj6h-64fc-37mp` before expiration
  - enforce release protection rules
  - execute and record maintainer verification runbook

### Semantic Search Roadmap
- Semantic index plan drafted and linked:
  - `docs/semantic_vector_index_plan.md`
- Current implementation status:
  - Phase A complete (local derived index + profile-scoped manifest/records + config flag)
  - Phase B baseline complete (CLI + API surfaces + initial tests)
  - Phase C complete baseline (legacy + TUI v2 semantic workflows and mode toggles)
  - Next: incremental mutation hooks + hybrid quality hardening

## 4) Recommended Next Steps (Priority Order)

1. Continue feature-development parity polish in TUI v2 with user-driven UX gaps.
: prioritized gaps from side-by-side legacy vs v2 run:
: onboarding + stats/ops + lock/session affordances now landed; focus now is mockup-aligned UI refresh completion.
2. Complete Phase 5 TUI v2 UI refresh queue:
: final visual polish pass (profile tree navigation/select is now landed).
3. Add semantic incremental update hooks on entry/link/tag mutations.
4. Raise TUI v2 critical-path coverage beyond current gate floor (target >82% for `src/seedpass/tui_v2/app.py`).
5. Expand semantic hybrid quality validation and KB stress evidence capture.
6. Advance Nostr resilience validation with optional real-relay soak lane after deterministic suites.

## 5) Next Slice Definition (Recommended Immediate Work)

### Slice A: “Post-Parity Cutover Readiness”

Deliverables:
- Keep parity docs in sync with shipped behavior and evidence.
- Raise test gates/coverage thresholds for the TUI v2 critical path.
- Capture remaining cutover blockers as explicit release criteria.

Exit criteria:
- Matrix exists, reviewed, and linked from this document.
- New tests pass in CI-equivalent run.
- Remaining parity gaps are explicit and severity-ranked.

Progress update (2026-03-02):
- Matrix added: `docs/tui_v2_legacy_parity_matrix.md`
- Managed-account session parity landed in TUI v2:
  - `managed-load (optional: entry_id)`
  - `managed-exit`
  - service wrappers and tests added
- Nostr maintenance parity landed in TUI v2:
  - `nostr-reset-sync-state`
  - `nostr-fresh-namespace`
  - service wrappers and tests added
- Nostr pubkey utility parity landed in TUI v2:
  - `npub` (alias: `nostr-pubkey`)
  - displays active profile npub (+ QR payload) in sensitive panel
  - tests added for success and validation paths
- Full legacy workflow coverage closed with bug-bash evidence:
  - `python scripts/ai_tui2_agent_test.py --scenario extended --verbose` => PASS
  - `python scripts/ai_tui_agent_test.py --scenario extended --verbose` => PASS
- Coverage gates strengthened for TUI v2 critical path:
  - `scripts/run_ci_tests.sh` now enables critical coverage gate by default.
  - `scripts/check_critical_coverage.py` default thresholds now include `src/seedpass/core/api.py=85`.
  - new focused gate `scripts/tui2_coverage_gate.sh` enforces:
    - `src/seedpass/tui_v2/app.py >= 78%`
    - `src/seedpass/core/api.py >= 85%`
- Nostr deterministic resilience suite expanded:
  - new tests in `src/tests/test_nostr_resilience_failure_modes.py` cover:
    - no encrypted data sync attempt
    - publish-without-event fallback error handling
    - preservation of relay-provided publish errors
    - snapshot-missing warning path
    - snapshot-fetch exception warning path
- Cutover memo refreshed with current gate status and blockers:
  - `docs/tui_v2_cutover_decision.md` updated (March 2, 2026)
  - documents parity-complete status, strengthened CI gates, and remaining hardening blockers
- Supply-chain and runbook docs centralized for closure work:
  - `docs/release_verification_runbook.md`
  - `docs/release_protection_policy.md`
  - `docs/operational_runbooks.md`
  - `docs/staged_rollout_runbook.md`
  - `docs/agent-handoffs/incidents/2026-02-15-relay-health-preflight-job.md`
- Discoverability parity improved in TUI v2:
  - added full palette command reference (`help-commands`, alias `commands`)
  - `help` now also renders in-app command reference in entry detail pane
  - focused TUI gate remains green with improved app coverage (`79.97%`)
- Session affordance parity improved in TUI v2:
  - added `session-status`, `lock`, and `unlock <password>` palette commands
  - left pane now displays explicit session lock state and managed-session indicator
  - lock state blocks open/reveal/QR workflows until unlock succeeds
  - interaction + matrix tests extended for usage, success, and failure paths
- UI refresh progress (mockup-aligned) now in active implementation:
  - shell scaffold + top ribbon + action strip
  - grid modernization (table-like rows/heading)
  - core + advanced inspector boards
  - advanced inspector actions: `copy <field> (optional: confirm)` and `export-field <field> <path> (optional: confirm)`
  - density controls: `d` key and `density <compact|comfortable>`
  - profile tree scaffold visible in left pane
- Online-mode defaults updated:
  - profiles now default to online (`offline_mode = false` by default)
  - one-time onboarding notice added for first online profile load with settings guidance

Current UI refresh remaining queue:
1. Final visual polish pass against mockups (spacing, headers, action strip clarity).
2. Tune semantic indicator wording/placement in top ribbon/action strip for readability under narrow terminals.

## 6) Working Rule

When priorities conflict:
1. Keep CI green.
2. Close user-visible parity gaps.
3. Raise security/testing gates.
4. Then optimize docs and process.
