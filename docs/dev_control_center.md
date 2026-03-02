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

## 2) Canonical Status Sources

Use these docs as inputs, but treat this file as the decision layer:

- TUI v2 plan: `docs/tui_v2_plan.md`
- TUI parity backlog: `docs/tui_v2_parity_backlog.md`
- TUI parity checklist: `docs/tui_v2_parity_checklist.md`
- TUI legacy parity matrix: `docs/tui_v2_legacy_parity_matrix.md`
- Cutover memo: `docs/tui_v2_cutover_decision.md`
- Security readiness: `docs/security_readiness_checklist.md`
- Supply-chain integrity: `docs/supply_chain_release_integrity.md`
- QA roadmap: `docs/agent_testing_roadmap.md`
- Agent TUI testing: `docs/ai_agent_tui_testing.md`
- KB scale validation: `docs/kb_scale_validation.md`
- Beta hardening report: `docs/beta_hardening_2026-03-02.md`

## 3) What Is Still Open

### Parity / Product
- `docs/tui_v2_parity_checklist.md` still marks:
  - Full legacy workflow coverage: **Pending**

### Security Readiness
- `docs/security_readiness_checklist.md` still marks:
  - #4 Backup/restore integrity: **In Progress**
  - #5 Nostr sync security/resilience: **In Progress**
  - #7 Testing gates/quality thresholds: **In Progress**
  - #8 Supply chain/release integrity: **In Progress**
  - #9 Operational runbooks: **Not Started**
  - #10 External audit/rollout: **Not Started**

### Supply Chain Specific
- `docs/supply_chain_release_integrity.md` remaining work:
  - execute at least one tagged production release through integrity workflow and record evidence
  - resolve/document exception `GHSA-wj6h-64fc-37mp`
  - enforce release protection rules
  - add/validate maintainer verification runbook

## 4) Recommended Next Steps (Priority Order)

1. Close remaining TUI v2 legacy parity gap with an explicit action matrix and tests.
2. Strengthen testing gates by adding critical coverage thresholds for TUI v2 and key service modules used by v2.
3. Advance Nostr resilience validation with deterministic failure-mode suites (then optional real-relay soak lane).
4. Update cutover memo to reflect current reality and remaining concrete blockers.
5. Finish supply-chain readiness evidence and release-protection policy.

## 5) Next Slice Definition (Recommended Immediate Work)

### Slice A: “Legacy Parity Closure Matrix”

Deliverables:
- Add `docs/tui_v2_legacy_parity_matrix.md` mapping legacy interactive actions to TUI v2 equivalents (or explicit gaps). ✅ (initial matrix added)
- Add tests for any currently uncovered high-value legacy actions surfaced by that matrix.
- Update `docs/tui_v2_parity_checklist.md` to remove or narrow “Full legacy workflow coverage: Pending”.

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
- Current next implementation target:
  - explicit Nostr sync-state reset/fresh-namespace parity commands

## 6) Working Rule

When priorities conflict:
1. Keep CI green.
2. Close user-visible parity gaps.
3. Raise security/testing gates.
4. Then optimize docs and process.
