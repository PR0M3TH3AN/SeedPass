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
    - [x] **Secure Data Parity:** Full support for reveal/QR/copy across Passwords, TOTP, SSH, PGP, Nostr, Seeds, and Documents.
    - [x] **Managed Sessions:** `ml` (Load) and `mx` (Exit) parity for BIP-85 sub-profiles.
    - [x] **Semantic Search:** Integration of `SemanticIndexService` into the TUI v3 grid with mode switching (Keyword, Hybrid, Semantic).
    - [x] **Entry Lifecycle:** Unified `AddEntryScreen`, `SeedPlusScreen` for derivations, and `DocumentEditScreen`.
    - [x] **Grid Filtering:** Filter presets (secrets, docs, keys, 2fa) and Archive toggle (`archived`).

---

## 3. Remaining Roadmap

### Phase A: Action Parity (COMPLETED)
- [x] **Clipboard Integration:** `c` copies primary fields (Password, TOTP, PubKey, nsec, etc) as per v3 mockups.
- [x] **Archive/Restore:** `a` toggle wired with grid refresh.
- [x] **Managed Account Loading:** Full load/exit parity with reactive fingerprint updates.
- [x] **Edit Workflows:** Unified `EditEntryScreen` implemented to support all types.

### Phase B: High-Fidelity Refinement
- [ ] **Mockup 1:1 Polish:** Final pass on spacing/density for all 9 PNG mockups.
- [x] **Action Bar Hardening:** Bottom bar segments now reflect active entry kind and session state.
- [x] **Notifications:** Unified snackbar/toast system for service feedback.
- [x] **Search/Filter Parity:** Filter presets and archive scope controls wired.

### Phase C: Advanced Features
- [x] **Semantic Search Integration:** Mode chips connected to `SemanticIndexService`.
- [x] **Nostr Relay Management:** Dedicated screen/board for relay status and synchronization.

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
- **Secure Data Parity:**
    - Completed `_resolve_sensitive_payload` for SSH, PGP, Nostr, Key-Value, and Documents.
    - Updated `derive_pgp_key` and API to support armored PGP Public Key retrieval/copying.
    - Aligned copy/reveal semantics with mockup hints (e.g., SSH/PGP copy Pub by default).
- **Managed Sessions:**
    - Added `action_managed_load` (`m`) and `action_managed_exit` (`Shift+M`) to v3.
    - Wired `ml` and `mx` commands to the palette.
- **Search & Filters:**
    - Integrated `SemanticIndexService` into `EntryDataTable`.
    - Added `filter <kind>` (secrets, docs, keys, 2fa) and `archived` view toggle.
    - Updated `GridMetrics` to show active filter, archive status, and search mode.
- **Entry Lifecycle:**
    - Implemented `AddEntryScreen` (unified wizard) and `SeedPlusScreen` (BIP-85 derivations).
    - Implemented `DocumentEditScreen` with full-screen editor and Ctrl+S save path.
    - Added `action_export_selected` (`x`) for document-to-disk parity.
- **UX & Hardening:**
    - Made `ActionBar` dynamic based on entry kind and managed session state.
    - Expanded v3 parity tests in `src/tests/test_tui_v3_parity.py` (Reveal/Copy/Archive/Add/Filter).
    - Fixed PGP key tuple alignment across `manager.py`, `api.py`, `entry_management.py`, and TUI v2.

- **Nostr Integration:**
    - Completed Relay Management screen `src/seedpass/tui_v3/screens/relays.py`.
    - Added `[R]efresh`, `[D]elete`, and `[S]ync Now` capabilities.
    - Wired `relay-list` palette command to trigger interface.
- **Notifications:**
    - Confirmed Textual's standard `app.notify()` satisfies the notification queue mockups uniformly across all TUI v3 screens.
- **Data I/O & Entry Lifecycle:**
    - Expanded `EditEntryScreen` to support viewing and modifying all entry kind fields seamlessly without throwing unimplemented errors.
    - Extended `action_export_selected` to save individual `SSH`/`PGP`/`Nostr` key pairs and `TOTP` secrets directly to file identically to TUI v2.
    - Integrated `db-export` and `db-import` routines into the CommandPalette processor to reach 100% Vault I/O parity.

### Validation evidence
- `pytest -q src/tests/test_tui_v3_parity.py` -> `4 passed`
- All reveal/QR/copy semantics verified for high-risk kinds.
- PGP Public key support confirmed in both TUI v2 and v3.
- Nostr relay actions mapped back through internal configuration via `app.services['nostr']`.
