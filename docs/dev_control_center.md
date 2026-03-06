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
  - latest result: `35 passed`
  - includes profile-tree keyboard navigation/select command coverage

## 2) Canonical Status Sources

Use these docs as inputs, but treat this file as the decision layer:

- TUI v2 plan: `docs/tui_v2_plan.md`
- TUI parity backlog: `docs/tui_v2_parity_backlog.md`
- TUI parity checklist: `docs/tui_v2_parity_checklist.md`
- TUI legacy parity matrix: `docs/tui_v2_legacy_parity_matrix.md`
- TUI v2 UI refresh plan (mockup-aligned): `docs/tui_v2_ui_refresh_plan.md`
- TUI v2 integration execution plan (current working plan): `docs/tui_v2_integration_execution_plan_2026-03-02.md`
- TUI v2 mockup gap audit: `docs/tui_v2_mockup_gap_audit_2026-03-02.md`
- Semantic vector index integration plan: `docs/semantic_vector_index_plan.md`
- Index0 atlas execution plan: `docs/index0_atlas_execution_plan_2026-03-05.md`
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

### Index0 Atlas Roadmap
- New architecture/spec track drafted:
  - `docs/index0_atlas_execution_plan_2026-03-05.md`
- Phase 0 implementation spec drafted:
  - `docs/index0_phase0_spec_2026-03-05.md`
- Phase 1 foundation slice landed:
  - reserved `_system.index0` namespace normalization
  - deterministic `index0` merge helper
  - Nostr manifest optional `index0` metadata support
  - focused tests in `src/tests/test_index0_core.py`
- Intent:
  - add canonical encrypted atlas state inside the existing payload for audit, hierarchy wayfinding, and future KB/chat navigation
- Key implementation direction:
  - reserved `_system.index0` namespace inside the synced payload
  - deterministic merge + checkpointed hash-chain validation
  - rebuildable wayfinder views layered on top
- Sequencing:
  - Phase 0 spec/schema is drafted
  - Phase 1 foundation is partially implemented
  - next implementation slice: event emission hooks from entry CRUD/link flows
  - implementation phases should not preempt current TUI cutover-critical or security-readiness blockers

## 4) Recommended Next Steps (Priority Order)

1. Execute Phases A-C from `docs/tui_v2_integration_execution_plan_2026-03-02.md`:
: selection lifecycle, real hierarchy tree, and dense header/footer rebuild.
2. Execute Phases D and G:
: filter menu model and reveal/QR reliability hardening.
3. Execute Phase H:
: responsive and density polish for high-resolution and compact terminals.
4. Execute Phase E:
: unified lexical+tag+semantic search integration.
5. Execute Phase F:
: final per-board fidelity pass and strict mockup closeout.
6. Start Index0 Atlas Phase 0 from `docs/index0_atlas_execution_plan_2026-03-05.md`:
: lock schema, merge contract extension, manifest checkpoint fields, and compaction rules.
7. After cutover-critical TUI/security slices stabilize, execute Index0 Atlas Phases 1-3:
: canonical storage, event emission hooks, and manifest checkpoint validation.
8. After semantic hardening resumes, execute Index0 Atlas Phase 5:
: atlas read APIs/views and semantic interplay.

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
1. Keep strict mockup parity `Open` count at zero:
: preserve 2FA `copy URL` command/board affordance coverage.
2. Finish remaining `Minor Gap` board polish:
: `UI Board`, `Password`, `Stored Password`, `Note` geometry/rhythm and action-chip treatment.
3. Final UI-board density/viewport balance polish:
: keep both dense table rows and usable lower inspector in common terminal sizes.
4. Continue semantic indicator wording/placement tuning (baseline compact ribbon pass is now landed) for readability under narrow terminals.
5. Execute strict closeout pass from:
: `docs/tui_v2_ui_refresh_plan.md` section "15) Mockup Board Parity Audit (2026-03-02)".
4. Keep default list focus + hotkey reliability + compact responsive regression green:
: `test_tui2_textual_default_focus_keeps_sensitive_hotkeys_active`.
: `test_tui2_textual_compact_layout_hides_link_panel_and_can_restore`.
5. Keep SSH/PGP/Nostr board-fidelity regression green:
: `test_tui2_textual_ssh_pgp_nostr_boards_show_action_fidelity`.
6. Keep Seed/Managed Seed board-fidelity regression green:
: `test_tui2_textual_seed_and_managed_seed_boards_show_fidelity`.
7. Preserve micro-alignment density (table/header/panel spacing) in ongoing UI slices.
8. Keep Note/2FA metadata consistency regression green:
: `test_tui2_textual_note_and_totp_boards_include_common_metadata`.
9. Preserve table/header/action micro-copy consistency introduced in latest polish.
10. Track strict closeout statuses (`Done` / `Minor Gap` / `Open`) per board and re-evaluate after each slice.
11. Keep compact discoverability regression green (inline notes/tags fallback when side card is collapsed).
12. Keep viewport-height balance regression green (activity fallback + layout rebalance on short screens).
13. Preserve icon-enhanced board title hierarchy introduced in typography polish pass.
14. Keep strict scorecard at `Open=0` and advance `Minor Gap -> Done` boards incrementally.

## 6) Working Rule

When priorities conflict:
1. Keep CI green.
2. Close user-visible parity gaps.
3. Raise security/testing gates.
4. Then optimize docs and process.

## 7) Active UI Parity Focus (Mockup-Coupled)

Use this order for current TUI v2 design iterations:

1. Preserve upper table density while retaining usable lower inspector in the same viewport.
2. Normalize shared inspector header metadata/actions across all kinds.
3. Complete board-specific action affordance fidelity:
: Password/Stored Password -> Note/2FA -> Seed -> SSH/PGP/Nostr.
4. Keep each slice test-gated:
: `poetry run pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py`
5. Capture screenshot evidence after each slice in:
: `artifacts/ui_eval/current_tui2_after*.png`.
