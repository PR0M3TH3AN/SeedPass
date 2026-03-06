# SeedPass Dev Control Center

Last updated: 2026-03-06  
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
  - `./.venv/bin/pytest -q src/tests/test_tui_v3_smoke.py src/tests/test_tui_v3_parity.py src/tests/test_typer_cli.py`
  - latest result in the current v3/default-launch track: `77 passed`
  - latest focused v3 UX/context regression slice: `18 passed`

## 2) Canonical Status Sources

Use these docs as inputs, but treat this file as the decision layer:

- TUI v3 plan (current working UI roadmap): `docs/tui_v3_plan.md`
- TUI v2 plan: `docs/tui_v2_plan.md`
- TUI v2 artifacts remain logic/reference material only unless explicitly reactivated
- Semantic vector index integration plan: `docs/semantic_vector_index_plan.md`
- Index0 atlas execution plan: `docs/index0_atlas_execution_plan_2026-03-05.md`
- Atlas/search/graph integration plan: `docs/atlas_search_graph_integration_plan_2026-03-05.md`
- Nostr communications future capability reference: `docs/nostr_comms_reference_and_future_capability_2026-03-05.md`
- Cutover memo: `docs/tui_v2_cutover_decision.md`
- Security readiness: `docs/security_readiness_checklist.md`
- Supply-chain integrity: `docs/supply_chain_release_integrity.md`
- QA roadmap: `docs/agent_testing_roadmap.md`
- Agent TUI testing: `docs/ai_agent_tui_testing.md`
- KB scale validation: `docs/kb_scale_validation.md`
- Beta hardening report: `docs/beta_hardening_2026-03-02.md`

## 3) What Is Still Open

### Parity / Product
- TUI v3 is now the default launch target (`seedpass` -> v3).
- TUI v3 now owns:
  - startup profile selection / unlock
  - add-new / recover / restore onboarding
  - inspector boards and context-aware lower pane behavior
  - default-shell UX work
- TUI v2 remains available via `seedpass tui2`, but is no longer the active UI development target.
- Remaining v3 parity/hardening gaps still visible from the shipped code:
  - context-aware action strip should continue being tightened per entry kind
  - restore / import guidance and final visual polish still need iteration
  - additional legacy utility and maintenance affordances should continue moving into v3 screens where they improve discoverability
  - profile-management flows now exist in-app, but still need broader polish around naming, confirmations, and operator guidance
  - maintenance screens now have shared styling/status helpers, but still need final mockup-level polish and any future screens should adopt the shared pattern from the start

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

### Search / Graph Integration Roadmap
- New cross-system plan drafted and linked:
  - `docs/atlas_search_graph_integration_plan_2026-03-05.md`
- Purpose:
  - unify `index0`, tags, links, and local semantic search into one search/navigation model
- Phase A baseline landed:
  - `SearchService` added in `src/seedpass/core/api.py`
  - unified result payload with score breakdown, match reasons, safe excerpts, tags, and linked-hit summaries
  - deterministic filter/sort pipeline added for keyword / hybrid / semantic search modes
  - v3 entry grid now routes through the unified search path instead of branching search logic in the widget layer
  - focused regression coverage added in `src/tests/test_core_api_services.py` and `src/tests/test_tui_v3_smoke.py`
- Phase B baseline landed:
  - `SearchService.linked_neighbors(...)` and `relation_summary(...)` now provide explicit outgoing/incoming graph navigation data
  - v3 grid now preserves active search query across refresh/filter/sort changes
  - v3 grid now exposes explicit in-app filter/mode/sort controls instead of palette-only command flow
  - v3 inspector now includes a linked-items panel with direct open-entry actions
  - focused regression coverage expanded in `src/tests/test_core_api_services.py` and `src/tests/test_tui_v3_smoke.py`
- Next planned implementation:
  - deeper linked-navigation workflows and richer graph-oriented pivots
  - deeper atlas/search handoff and graph-aware result workflows

### Future Capability: Nostr Communications
- Research/reference doc added:
  - `docs/nostr_comms_reference_and_future_capability_2026-03-05.md`
- Purpose:
  - capture the relevant NIPs for future DMs and team/community chat in SeedPass
  - align that capability with managed deterministic identities, `index0`, and future institutional knowledge workflows
- Current planning direction:
  - prefer `NIP-17` + `NIP-44` + `NIP-59` for private DMs
  - evaluate `NIP-29` as the strongest candidate for managed institutional group chat
  - treat `NIP-28` and `NIP-72` as public/community-oriented layers
- Not current implementation work:
  - this is documented as a future addition and should not preempt the current v3/search/index0/security priorities

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
- Phase 1 CRUD/link emission slice landed:
  - deterministic `index0_event` emission from entry create/modify/archive/restore/delete flows
  - deterministic `index0_event` emission from link add/remove flows
  - writer-head updates and hierarchy-aware scope derivation from active profile path
  - focused regression coverage in `src/tests/test_index0_events.py`
- Phase 1 checkpoint/manifest slice landed:
  - deterministic daily checkpoint rebuild from canonical `index0_event` streams
  - bounded checkpoint retention per writer
  - manifest `index0` publication of checkpoint hashes and stream heads during sync
  - focused regression coverage in `src/tests/test_index0_checkpoints.py`
- Phase 1 canonical views slice landed:
  - deterministic synced `children_of`, `counts_by_kind`, and `recent_activity` views
  - view rebuild runs in the same compaction path as checkpoints
  - lightweight atlas read helpers landed in core
  - focused regression coverage in `src/tests/test_index0_views.py`
- Atlas consumer slice landed:
  - `AtlasService` added in `src/seedpass/core/api.py`
  - v3 palette can open an atlas/wayfinder screen backed by the service layer
  - v3 main workspace now shows an always-visible atlas strip in the shell chrome
  - v3 atlas screen now supports direct entry jumps and quick filter jumps
  - focused regression coverage updated in `src/tests/test_core_api_services.py` and `src/tests/test_tui_v3_smoke.py`
- Current accomplishments summary:
  - v3 is the default UI and owns unlock/onboarding/maintenance/profile/security flows
  - semantic index is integrated as a local derived retrieval layer
  - canonical tags and typed links already exist at the entry model level
  - `index0` now covers canonical atlas events, checkpoints, manifest metadata, synced views, service reads, and first v3 consumers
- Intent:
  - add canonical encrypted atlas state inside the existing payload for audit, hierarchy wayfinding, and future KB/chat navigation
- Key implementation direction:
  - reserved `_system.index0` namespace inside the synced payload
  - deterministic merge + checkpointed hash-chain validation
  - rebuildable wayfinder views layered on top
- Sequencing:
  - Phase 0 spec/schema is drafted
  - Phase 1 foundation + CRUD/link emission + checkpoint/manifest publication + first canonical views are implemented
  - atlas read service layer and first v3 consumers are implemented
  - first actionable v3 wayfinder navigation flows are implemented
  - next implementation slice: broader agent-facing atlas workflows and deeper search/navigation handoff, plus any later event-pruning compaction policy
  - implementation phases should not preempt current TUI cutover-critical or security-readiness blockers

## 4) Recommended Next Steps (Priority Order)

1. Execute the remaining active v3 parity slices from `docs/tui_v3_plan.md`:
: context-aware actions, maintenance affordances, and final board fidelity polish.
2. Continue TUI v3 utility/maintenance carryover:
: remaining settings-linked operational flows, discoverable security maintenance, and final maintenance-screen mockup polish passes.
3. Continue v3 startup/restore hardening:
: clearer restore warnings, success summaries, and import/recovery guidance.
4. Continue Phase B/C from `docs/atlas_search_graph_integration_plan_2026-03-05.md`:
: deeper v3 search/navigation handoff, graph pivots, and next-level linked-item workflows.
5. Resume Index0 Atlas and graph follow-on work after current v3 UX slices stabilize:
: agent-facing atlas workflows, linked-item navigation, deeper search/navigation handoff, and any later event-pruning compaction policy.
6. Continue security-readiness blockers in parallel where they do not conflict with the v3 path.

## 5) Next Slice Definition (Recommended Immediate Work)

### Slice A: “Search Graph Navigation”

Deliverables:
- Extend the new linked-neighbor and relation-summary methods with deeper graph pivots above the current atlas/search foundations.
- Continue iterating on the new explicit v3 sort/filter controls on top of the unified `SearchService`.
- Expand the new inspector linked-item navigation so users can pivot through relationships more fluidly without raw JSON inspection.
- Keep the atlas/search/graph plan and control center synchronized with shipped behavior as this slice lands.

Exit criteria:
- one service-layer path can return linked neighbors and relation summaries for an entry
- v3 exposes explicit sort/filter affordances instead of relying only on command-state
- linked items can be viewed and opened from the inspector
- focused search/atlas/v3 suites stay green

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
