# TUI v3 Modular Architecture & Parity Plan

Last updated: 2026-03-03  
Branch target: `beta`  
Status: Active (Parity execution in progress)

## 1. Context & Rationale
SeedPass has transitioned from TUI v2 to **TUI v3 (Scratch Rebuild)**. 

### Why we moved on from v2:
*   **The Monolith Problem:** `tui_v2/app.py` exceeded 6,500 lines, making it impossible to maintain or refactor without significant regression risk.
*   **Crowded Layout:** v2 attempted to fit all views (Settings, Detailed Inspection, Grid) into a single frame, violating the professional application feel of the mockups.
*   **Brittle Interaction:** Action Strip click detection and manual string-painting led to a "ghost button" feel.
*   **V3 Solution:** Modular files (`widgets/`, `screens/`), proper Textual `push_screen` transitions, and a reactive "Board Architecture."

*Note: The v2 plan (`docs/tui_v2_plan.md`) remains active as a logic reference, but UI/UX development is now focused here.*

---

## 2. Current Progress (The Foundation)
We have successfully scaffolded the core v3 shell:

- [x] **Modular Architecture:** Established `src/seedpass/tui_v3/` with sub-directories.
- [x] **Factory Injection:** Reused all existing service hooks (Entry, Vault, Profile).
- [x] **App Shell:** Working `MainScreen` with Sidebar, Header, Grid, and Inspector.
- [x] **Full-Screen Transitions:** Working `SettingsScreen` and `MaximizedInspectorScreen`.
- [x] **Board Architecture:** Implemented specialized ASCII cards for:
    - [x] Passwords
    - [x] Notes / Documents
    - [x] TOTP (with live ticking timer)
    - [x] BIP-39 Seeds
    - [x] SSH / PGP / Nostr / Key-Value
- [x] **Core Interaction:** 
    - [x] Command Palette (Ctrl+P) with command routing.
    - [x] Reveal (v) and QR (g) logic with double-press confirmation.
    - [x] Reactive Search and Selection.

---

## 3. Remaining Roadmap

### Phase A: Action Parity
- [~] **Clipboard Integration:** `c` is now wired through v3 action + palette path, but per-kind field targeting and confirm-gated high-risk copy parity are still incomplete.
- [~] **Archive/Restore:** `a` is wired and refreshes grid state; needs broader regression coverage across kinds and locked-session edge paths.
- [~] **Managed Account Loading:** profile-tree child node routing now opens `managed:<id>`/`agent:<id>` entries correctly; full managed session load/exit parity is still pending.
- [ ] **Edit Workflows:** Implement a dedicated `EditScreen` or integrate the v2 editor.

### Phase B: High-Fidelity Refinement
- [ ] **Mockup 1:1 Polish:** Final pass on spacing/density for all 9 PNG mockups.
- [ ] **Action Bar Hardening:** Ensure all clickable segments in the bottom bar route to the new v3 actions.
- [ ] **Notifications:** Unified snackbar/toast system for service feedback.

### Phase C: Advanced Features
- [ ] **Semantic Search Integration:** Connect the "Search Mode" chips to the `SemanticIndexService`.
- [ ] **Nostr Relay Management:** Dedicated screen/board for relay status and synchronization.

---

## 4. Functional Parity Protocol
To finalize v3, we must verify 100% functional parity with the **Legacy TUI**.

### Test Checklist:
1.  **Vault Setup:** Initialize profile, Change Password, Lock/Unlock.
2.  **Entry Lifecycle:** Create (all types), Edit, Search, Archive, Restore, Delete.
3.  **Secure Data:** Reveal (v), QR (g), Copy (c) across all high-risk types.
4.  **Sub-profiles:** Load managed account, exit managed account, nested hierarchies.
5.  **Data I/O:** DB Export/Import, Document Export, TOTP Export.
6.  **Nostr Sync:** Fresh namespace, Relay management, Sync-now.

### Automation:
`scripts/interactive_agent_tui_test.py` now supports v3 execution and currently validates baseline flows (selection, reveal confirmation, screen transitions, archive/copy trigger path).  
Additional strict parity assertions are still required before cutover.

---

## 5. Progress Log (2026-03-03)

### Completed in this session
- Added v3 lock-state action parity surface:
  - palette commands: `session-status`, `unlock <password>`, `lock`.
  - app actions: `action_session_status`, `action_lock`, `action_unlock`.
- Fixed v3 default startup lock blocker:
  - `session_locked` now defaults to `False` for preflighted/injected service runtime.
- Fixed v3 QR rendering runtime defect:
  - added local `render_qr_ascii(...)` helper in `tui_v3/app.py`.
- Fixed profile-tree child selection semantics:
  - `managed:<id>` / `agent:<id>` now open entries instead of incorrectly switching active fingerprint.
- Fixed v3 screen query scope bug:
  - replaced app-root widget lookups with `self.screen.query_one(...)` for screen-mounted widgets.
  - this unblocked reveal/inspector synchronization and removed silent no-op behavior masked by broad exception handlers.
- Added grid focus refresh behavior:
  - `EntryDataTable.on_focus()` now refreshes runtime rows.
- Added new v3 smoke tests:
  - `src/tests/test_tui_v3_smoke.py` with coverage for lock/unlock/session-status, child-node entry opening, and grid focus refresh.

### Validation evidence
- `pytest -q src/tests/test_tui_v3_smoke.py` -> `3 passed`.
- `python scripts/interactive_agent_tui_test.py --version v3`:
  - seed confirmation prompt appears on first `v`.
  - seed reveal succeeds on second `v`.

---

## 6. Remaining Work (Ordered)

1. Complete secure-data parity for all high-risk kinds
- finish `_resolve_sensitive_payload` support for SSH/PGP/Nostr and related reveal/copy semantics.
- align per-kind copy behavior with board/action hints.

2. Implement managed session parity commands
- `managed-load` / `managed-exit` equivalent behavior in v3 command surface.
- ensure nested managed-account lifecycle mirrors legacy/v2 expectations.

3. Implement edit + export workflows
- document edit screen/path.
- field export and document export command parity.

4. Bring search/filter parity to v3
- filter presets, archive scope controls, and search-mode wiring.
- semantic mode chips connected to actual semantic service behavior.

5. Hardening and UX fidelity
- action bar truthfulness (only show actions that are actually wired).
- notification consistency and failure-state recovery messaging.

6. Expand automated parity coverage
- grow v3 tests to cover reveal/QR/copy across all major kinds, managed lifecycle, and archive/filter edge paths.
