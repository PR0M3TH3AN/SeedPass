# Memory Update (2026-03-03)

## Architectural Pivot: TUI v3 Scratch Rebuild
- **Decision:** Shifted development from TUI v2 to TUI v3.
- **Rationale:** v2 became a monolithic "God Object" (>6,500 lines). v3 uses a modular architecture with separate files for `widgets/` and `screens/`.
- **Layout Solution:** Moved from "all-in-one-frame" to a **Screen-based transition** model.
    - `SettingsScreen`: Full-screen configuration.
    - `MaximizedInspectorScreen`: Full-screen focused detail (bound to `z`).
- **Board Architecture:** Implemented specialized ASCII boards (e.g., `TotpBoard`, `SshBoard`) that reactively swap in the inspector based on the selected entry kind.

## Technical Insights & Fixes
- **Action Strip Hardening:** Discovered that Textual widget borders and padding offset click coordinates. Fix: subtract border/padding widths from `event.x/y` before parsing segments.
- **Reactive Selection:** Used `on_data_table_row_highlighted` in v3 to trigger real-time inspector updates. This provides a much smoother feel than requiring a manual "open" command.
- **Confirmation Logic:** Hardened the "double-press" mechanism for high-risk actions (Seeds/Reveal). Replaced subtle status messages with bold "CONFIRMATION REQUIRED" inspector cards.
- **Regression Fix:** Re-synchronized `test_tui_v2_parity_scenarios.py` tests. They previously assumed auto-selection of filtered results, which is no longer the default behavior.

## Infrastructure
- **Test Centralization:** Created `docs/TEST_INVENTORY.md`.
- **Interactive Harness:** Created `scripts/interactive_agent_tui_test.py` which now supports both v2 and v3. It uses dependency injection to mock services, allowing for safe, password-free exploratory testing.
- **CLI Selector:** Updated root command to support `--tui [legacy|v2|v3]` and a direct `tui3` command.

## Next Steps for Future Sessions
- Implement the `EditScreen` in v3.
- Port the remaining Nostr Relay management logic to a dedicated v3 board.
- Complete the 1:1 pixel/character parity check against the 9 remaining mockups using the new `Board` classes.

## Audit Addendum (2026-03-03)
- Ran a v3 parity-focused static/runtime audit against v2 behavior contracts.
- Found a critical lock-state issue in v3: `session_locked` defaults to `True`, but v3 currently exposes `lock` only (no `unlock` action/command), which blocks reveal/archive/copy flows by default.
- Found a critical QR defect in v3: `action_show_qr` references `render_qr_ascii` without a local import/definition in `tui_v3/app.py`.
- Found parity gaps where inspector/action hints advertise workflows (`edit`, `export`, `sync`, `load session`, etc.) that are not currently wired in v3 keybindings/commands.
- Found v3 sensitive payload resolution is incomplete for high-risk kinds (SSH/PGP/Nostr), so copy/reveal behavior is not parity-complete.
- Confirmed the existing interactive harness can run v3, but secure reveal flow assertions currently fail in the script run output, reinforcing parity-blocker status.

## Applied Fixes (2026-03-03)
- v3 now includes a local `render_qr_ascii` helper in `tui_v3/app.py`, removing the unresolved symbol failure for QR rendering.
- v3 command processor now supports `session-status` and `unlock <password>`, and lock handling routes through dedicated app actions.
- Added `action_session_status`, `action_lock`, and `action_unlock` in v3 app with graceful service-capability checks.
- Set v3 default `session_locked` state to `False` so primary actions are not blocked at startup in injected-service and preflighted runtime flows.
- Fixed sidebar node selection handling so `managed:<id>` / `agent:<id>` opens the referenced entry instead of incorrectly mutating `active_fingerprint`.
- Fixed v3 widget lookup scope bugs by switching selection/refresh/palette/board updates from app-root `query_one(...)` to `self.screen.query_one(...)` for screen-mounted widgets.
- Added focus-refresh behavior for `EntryDataTable` so runtime-added entries appear immediately when the grid gains focus.
- Added `src/tests/test_tui_v3_smoke.py` covering:
  - palette lock/unlock/session-status command path
  - profile-tree child node selection semantics (`managed:<id>`, `agent:<id>`)
  - grid focus refresh behavior for runtime-added entries
- Re-ran interactive harness after fixes; seed reveal confirmation now works end-to-end in v3 walkthrough output.
