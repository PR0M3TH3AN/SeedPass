# Session Memory Update - 2026-03-02

## TUI v2 parity progress
- Completed multiple UI parity slices for Textual TUI v2 with focused test-gated increments.
- Current focused gate: `34 passed` for:
  - `src/tests/test_tui_v2_textual_interactions.py`
  - `src/tests/test_tui_v2_action_matrix.py`

## Key interaction fixes landed
- Resolved `v/g` reveal/QR hotkey reliability by defaulting center focus to `#entry-list`.
- Added regression: `test_tui2_textual_default_focus_keeps_sensitive_hotkeys_active`.

## Responsive behavior
- Added narrow-width compact mode behavior:
  - auto-collapses link side panel,
  - preserves secret panel,
  - shortens action-strip wording.
- Added regression: `test_tui2_textual_compact_layout_hides_link_panel_and_can_restore`.

## Board fidelity slices landed
- Password/Stored Password: explicit board naming and refined action/field lines.
- Note/2FA: metadata consistency and clearer action wording.
- SSH/PGP/Nostr: board titles, metadata-first layout, grouped actions.
- Seed/Managed Seed: specialized board titles, seed word-count fallback from phrase, confirm-gated action hints.
- Added regressions:
  - `test_tui2_textual_ssh_pgp_nostr_boards_show_action_fidelity`
  - `test_tui2_textual_seed_and_managed_seed_boards_show_fidelity`
  - `test_tui2_textual_note_and_totp_boards_include_common_metadata`

## Planning docs updated
- `docs/tui_v2_ui_refresh_plan.md`
  - Added strict closeout classification with `Done / Minor Gap / Open`.
  - Marked only explicit `Open`: 2FA board missing first-class `copy URL` affordance.
- `docs/dev_control_center.md`
  - Queue now prioritizes closing 2FA `copy URL`, then minor-gap visual polish and compact-mode discoverability.

## Artifact notes
- New UI evidence sets generated up to `after36` (SVG snapshot artifacts under `artifacts/ui_eval/`).
- Some prior `.png` files in artifacts were actually SVG payloads; prefer using `.svg` outputs from `export_screenshot` for reliable inspection in this workflow.

## Additional update (same session)
- Closed strict parity `Open` item for 2FA by adding first-class `2fa-copy-url <entry_id>`.
- Added TOTP URL support in generic copy path via `copy url confirm` for selected TOTP entries.
- Updated 2FA board/action hints and palette discoverability text to include URL copy flow.
- Implemented compact-mode notes/tags discoverability fallback inline in inspector boards when side panel is hidden.
- Extended compact layout test to assert inline notes/tags visibility.
- Current focused TUI gate remains green: `34 passed`.

## Additional update (viewport balance)
- Added height-adaptive viewport balance in TUI v2 responsive path.
- On short terminals, activity panel is hidden to preserve table/inspector usability.
- Added regression: `test_tui2_textual_viewport_balance_hides_activity_on_short_height`.
- Focused TUI suite now at `35 passed`.

## Additional update (typography/icon polish)
- Added consistent kind icons to inspector board titles/shared headers for faster visual scanning.
- Preserved behavior and command parity; change is presentational only.
- Generated `after40` SVG evidence set for all core boards.
- Focused TUI suite remains green at `35 passed`.

## Additional update (strict closeout scoring)
- Completed strict parity score pass in `docs/tui_v2_ui_refresh_plan.md`.
- Current board closeout state:
  - Done: 5 (`2FA`, `BIP-39 Seed`, `SSH`, `PGP`, `Nostr`)
  - Minor Gap: 4 (`UI Board`, `Password`, `Stored Password`, `Note`)
  - Open: 0
- Control center queue updated to target remaining Minor Gap boards first while preserving `Open=0`.
