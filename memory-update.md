# Memory Update (2026-03-02)

## TUI v2 mockup parity audit refreshed
- Added a dedicated audit doc: `docs/tui_v2_mockup_gap_audit_2026-03-02.md`.
- Linked the audit from `docs/tui_v2_ui_refresh_plan.md` so future sessions use it as the active parity reference.

## High-impact findings (user-visible)
- Inspector panel currently pre-populates because first entry is auto-selected; this diverges from context-aware mockup behavior.
- Left nav is not yet a true hierarchical tree of fingerprint -> managed-account nodes.
- Layout density and panel proportions still differ from mockup geometry, especially on large displays.
- Reveal/QR pathways exist in code but user runtime still reports non-working `v`/QR behavior in some installs; treat as high-priority runtime validation gap.

## Evidence artifacts to reuse
- Primary runtime evidence: `artifacts/ui_eval/audit_20260302/state_dump.txt`.
- Mockup baseline set: `UI_mockups/PNG/*.png` (all 1854x1080).

## Recommended next implementation slice
1. Remove initial auto-selection and use a neutral inspector state.
2. Implement true left-side hierarchy model.
3. Rework dense header/footer strips to mockup rhythm.
4. Tune spacing/label verbosity for higher effective density before adding new feature surface.

## Plan consolidation (2026-03-02)
- Created `docs/tui_v2_integration_execution_plan_2026-03-02.md` as the consolidated implementation roadmap.
- Captured user-priority requirements: context-aware inspector lifecycle, true fingerprint/managed/agent tree, collapsible sidebar, filter menu replacing always-visible kind toggles, and unified lexical+tag+semantic search.
- Reordered near-term execution toward structure and reliability first (Phases A-C, D, G, H), then semantic integration and final board-fidelity polish.

## Session Update (2026-03-02, evening)

### TUI v2 parity slices completed
- Added per-profile sidebar collapse persistence in `src/seedpass/tui_v2/app.py` (state now restores on `profile-switch` and `profile-tree-open`).
- Added search mode chips to grid heading and keyboard cycling (`m`) for `keyword -> hybrid -> semantic`.
- Improved reveal UX for confirm-required secrets (`seed`, `managed_account`, `ssh`, `pgp`): pressing `v` now arms confirm and pressing `v` again (within 8s) confirms reveal.
- Fixed profile tree label rendering glitch (`fp-aSeed:...`) by normalizing to `| Seed: ...` format.

### Regression coverage added
- Sidebar state restore per profile.
- Search-mode chip rendering + `m` hotkey cycle behavior.
- Managed-account reveal double-confirm keyboard flow.
- Profile-tree seed label formatting check.

### Verification status
- Focused TUI v2 gate is green at `45 passed` for:
  - `src/tests/test_tui_v2_textual_interactions.py`
  - `src/tests/test_tui_v2_action_matrix.py`
- New UI artifacts captured:
  - `artifacts/ui_eval/audit_20260302_phaseB2/`
  - `artifacts/ui_eval/audit_20260302_phaseE3/`
  - `artifacts/ui_eval/audit_20260302_phaseG2/`
  - `artifacts/ui_eval/audit_20260302_phaseB3/`

### Incremental parity progress (2026-03-02 late)
- Left profile tree now supports child-node traversal and open actions for managed/agent rows via `↑/↓/Ctrl+O`.
- Inspector behavior is more context-aware: non-sensitive kinds keep secret panel hidden by default and report clean unsupported-action status for `v`/`g`.
- Tree rendering now includes explicit group headers (`Managed Users`, `Agents`) to match mockup hierarchy clarity.
- Focused TUI gate remains stable at `46 passed` after these slices.
- Added CLI regression tests for legacy launch compatibility (`seedpass legacy`, `seedpass --legacy-tui`) in `src/tests/test_typer_cli.py` to guard installer/runtime fallback behavior.
- Added responsive high-resolution density mode for large viewports (notably 2256x1504 class), reducing chrome heights for brand/ribbon/status/action bars and heading rows to fit more working content.
- Tightened default vertical whitespace by removing extra top margin on status and TOTP board panels.
- Focused TUI gate after density updates: 47 passing tests.
- Added regression check for unsupported QR behavior on non-sensitive kinds (`document`) so `g` returns an explicit status message instead of ambiguous UI behavior.
- Added a unified right-pane mode switch path so document editor and 2FA board transitions remain mutually exclusive and state flags stay synchronized.
- Added regression test covering 2FA board -> document editor -> view transitions.
- Focused TUI gate now at 48 passing tests.
- Added context guard so opening an entry auto-closes 2FA board and blocks entry switching while document editor is active (prevents unsaved context drift).
- Added transition regression test for: 2FA board -> open entry (board closes) -> edit doc -> open other entry (blocked).
- Focused TUI gate now at 49 passing tests.
- Added dense high-res action strip mode with abbreviated global commands to reduce clipping and keep bottom controls readable on large viewports.
- Added regression assertions for dense action-strip activation/deactivation tied to responsive layout thresholds.
- Inspector heading is now context-aware and tracks right-pane mode: selected entry view, document editor, and 2FA board states.
- Added regression coverage for heading transitions across view/edit/2FA modes.
- Focused TUI gate now at 50 passing tests.
- Refined inspector board typography for password/document/TOTP kinds by grouping fields and operations into clearer compact sections (`Login Fields`, `Document Fields`, `2FA Fields`) to reduce visual clutter.
- Captured visual/state evidence in `artifacts/ui_eval/audit_20260302_phaseF6/`.
- Bottom action strip shortcuts are now functional and test-covered via new shift-shortcut actions mapped to palette command prefixes plus reveal action.
- Added focused artifact: `artifacts/ui_eval/audit_20260302_phaseH6/` for bottom action-strip validation.
- Added clickable action-strip routing: clicking top-row shortcut segments now triggers the same actions as keyboard shortcuts.
- Added regression test for action-strip click routing and captured artifact `artifacts/ui_eval/audit_20260302_phaseH7/`.
- Focused TUI gate now at 53 passing tests.
- Refined dense-mode top-left sidebar hierarchy: compact FP/profile/session scope lines plus reduced label noise while preserving tree navigation and status cues.
- Added artifact `artifacts/ui_eval/audit_20260302_phaseH8/` documenting the updated hierarchy.
- Continued board-rhythm parity pass: aligned TOTP field labels (`Period :`, `Digits :`) to match password/document row style and improve scan consistency.
- Added artifacts `audit_20260302_phaseF7` and `audit_20260302_phaseF8` for board layout comparison against mockups.
- Extended dense-mode action verbosity reduction across additional boards (seed/managed, ssh, pgp, nostr) for consistent low-noise inspector language.
- Improved profile-tree depth readability with active-branch counts (`M:x A:y`) and clearer child group connectors/labels.
- Added verification artifact `artifacts/ui_eval/audit_20260302_phaseB6/` for tree hierarchy scan quality.

## Session Update (2026-03-03)

### TUI v2 managed-session + action-strip reliability fixes
- Added managed-session breadcrumb tracking in `src/seedpass/tui_v2/app.py` so left header now shows nested path context:
  - `Path: <root-fingerprint> > <managed-fingerprint> > ...`
- Managed session state now tracks nested loads (`managed-load`) with stack semantics and restores the previous layer on each `managed-exit`.
- `managed-load` now normalizes kind tokens (`managed-account`, `managed account`, `managed_account`) to reduce false negatives.
- Action strip row-2 is now clickable (context actions), including:
  - `v` reveal
  - `g` QR
  - `e` edit
  - `a` archive
  - `6` 2FA board
  - `managed-load` / `managed-exit` when managed account is selected
- Added robust kind normalization for context rendering so action hints stay aligned with selected entry kind.

### Regression tests added/updated
- `test_tui2_textual_action_strip_click_routes_to_shortcuts` now validates row-2 click reveal.
- Added `test_tui2_textual_action_strip_context_updates_for_selected_kind` to ensure bottom context row updates by selection.
- Extended `test_tui2_textual_managed_account_session_palette_commands` with nested managed-load + breadcrumb assertions.

### Verification
- Focused and gate suite green:
  - `poetry run pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py`
  - Result: `56 passed`.

## Session Update (2026-03-03, Slice 2)

### UI-board density and hierarchy polish
- Dense high-resolution mode now keeps `#grid-heading` at 4 rows instead of 3 to avoid header/divider clipping in large viewports.
- Refined dense top-left header hierarchy to reduce line noise:
  - retained explicit `Fingerprint` and `Path`
  - consolidated session/profile/managed state into one line
  - kept scope line focused on active filters only

### Regression updates
- Updated `test_tui2_textual_hires_density_compacts_vertical_chrome` to assert the new dense grid-heading height (`4`).

### Verification
- Focused TUI v2 gate remains green:
  - `poetry run pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py`
  - Result: `56 passed`.

## Session Update (2026-03-03, Slice 3)

### Board geometry parity pass
- Added reusable ASCII card renderer for inspector sections (`_board_card`).
- Password and stored-password boards now render framed `Credentials` and `Quick Actions` blocks.
- Note/document boards now render framed `Content` and `Quick Actions` blocks.
- Increased note/document preview length (120 -> 180 chars) for better mockup-like content emphasis.

### Regression coverage
- Extended note metadata board test to assert card framing.
- Added password board card-section test.

### Verification
- Focused TUI v2 gate:
  - `poetry run pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py`
  - Result: `57 passed`.

## Session Update (2026-03-03, Slice 4)

### UI-board density rebalancing
- Added dynamic dense/high-res vertical split:
  - idle: `top-work=9fr`, `right=3fr`
  - active inspect/edit/2FA: `top-work=8fr`, `right=4fr`
- Added `_refresh_layout_balance()` and invoked it during key state transitions so layout rebalance is state-driven, not resize-driven.

### Regression coverage
- Added `test_tui2_textual_hires_density_rebalances_idle_vs_selected`.

### Verification
- Focused TUI v2 gate:
  - `poetry run pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py`
  - Result: `58 passed`.

## Session Update (2026-03-03, Slice 5)

### Action-strip microcopy polish
- Standardized context action wording to verb-first with key hints across entry kinds.
- Preserved managed account session actions while aligning adjacent wording style.
- Expanded row-2 click parser to recognize verb-led labels so copy changes do not break mouse interactions.

### Regression coverage
- Updated action-strip context tests to match polished copy.

### Verification
- Focused TUI v2 gate:
  - `poetry run pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py`
  - Result: `58 passed`.

## Session Update (2026-03-03, Slice 6)

### Universal card framing
- Extended `_board_card` to TOTP (Parameters), SSH/PGP/Nostr (Keys), and Seed/Managed (Seed Info) boards.
- All 9 board types now use consistent card-section visual language.
- Updated regression tests for SSH/PGP/Nostr, Seed/Managed, and TOTP boards.

### Verification
- Focused TUI v2 gate: `58 passed`.

### Next
- Capture fresh state dump/screenshots for updated boards.
- Update strict closeout scoreboard (Password/Stored Password/Note now at card parity; remaining Minor Gap items are density/rhythm only).

## Session Update (2026-03-03, Slice 7)

### Board density tightening
- Removed redundant section headers above card frames (saves 2-3 lines per board).
- Removed "Compact: Notes/Tags shown inline." noise from compact mode.
- Capped note preview at 100 chars (was 180) to prevent oversized Content cards.
- Password board now 17 lines (was ~21). All boards similarly tighter.

### Verification
- Focused TUI v2 gate: `58 passed`.

## Session Update (2026-03-03, Slice 8)

### Action strip + hint line tightening
- Normal-mode global row now uses verb-first labels matching context row style.
- Seed/TOTP Actions hints shortened from raw palette commands to user-facing verbs.
- All action hint lines now consistently use human-readable language.

### Verification
- Focused TUI v2 gate: `58 passed`.
