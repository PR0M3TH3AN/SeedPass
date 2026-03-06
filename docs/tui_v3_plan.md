# TUI v3 Modular Architecture & Parity Plan

Last updated: 2026-03-06  
Branch target: `beta`  
Status: Active (Default UI / parity hardening in progress)
Companion search/atlas plan: `docs/atlas_search_graph_integration_plan_2026-03-05.md`

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
    - [x] **Semantic Search:** Baseline `SemanticIndexService` integration landed and the main grid now routes through unified `SearchService` for keyword / hybrid / semantic search.
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
- [x] **Mockup 1:1 Polish:** Final pass on spacing/density for all 9 PNG mockups.
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
- [x] **1. Vault Setup:** Initialize profile, Change Password, Lock/Unlock.
- [x] **2. Entry Lifecycle:** Create (all types), Edit, Search, Archive, Restore, Delete.
- [x] **3. Secure Data:** Reveal (v), QR (g), Copy (c) across all high-risk types.
- [x] **4. Sub-profiles:** Load managed account, exit managed account, nested hierarchies.
- [x] **5. Data I/O:** DB Export/Import, Document Export, TOTP Export.
- [x] **6. Nostr Sync:** Fresh namespace, Relay management, Sync-now.

### Automation:
`scripts/interactive_agent_tui_test.py` has been fully extended in v3 execution. It now successfully validates all baseline flows including grid selection, 11 types of mock boards, sub-profile mounting, edit logic, text/secure data exports, and the global command palette processing logic. Parity assertions currently exit `0`.

---

## 5. Progress Log (2026-03-03)

### Completed in this session
- **Atlas / wayfinder progress:**
    - added a dedicated atlas wayfinder screen in v3
    - added an always-visible atlas strip to the main workspace shell
    - wired `AtlasService` through the service-layer boundary so v3 does not read raw atlas payloads directly
    - atlas screen now supports direct entry jumps and quick filter jumps
- **Unified search progress:**
    - added `SearchService` in the core service layer as the single search contract for v3 and future GUIs
    - v3 grid now uses the unified search path instead of branching between entry-service and semantic-service logic in the widget
    - baseline deterministic sorting, filtering, match reasons, and safe excerpts are now available in the normalized result payload
- **Index0 status alignment:**
    - current docs now reflect that `index0` foundations are implemented, not just planned
    - the next integration target is unified search, linked navigation, and deeper atlas/search handoff
- **Entry lifecycle parity:**
    - added `d` hotkey and `delete` palette command to v3.
    - delete now uses explicit double-press confirmation before removal.
    - successful delete clears the active selection and collapses the inspector again.
- **Nostr maintenance parity:**
    - added `npub` / `nostr-pubkey` utility flow in v3 with a dedicated screen showing the active profile pubkey and public QR payload.
    - added `nostr-reset-sync-state` and `nostr-fresh-namespace` palette commands to v3.
    - kept the implementation on top of `NostrService` rather than adding UI-specific core logic.
- **Security maintenance parity:**
    - added dedicated v3 flows for `change-password` and `backup-parent-seed`.
    - both screens submit through `VaultService` request models instead of reaching into manager internals.
    - settings now advertise the new security and backup maintenance commands for discoverability.
- **Profile management parity:**
    - added an in-app `profiles` flow for listing, switching, and removing non-active profiles.
    - profile mutations are routed through `ProfileService` request models.
    - app-level refresh behavior was hardened so maintenance screens can update state without assuming the main workspace is the active screen.
    - profile management now prefers display labels when available and requires a second remove action before deleting a non-active profile.
- **Restore/import guidance polish:**
    - create/recover flows now show more explicit mode guidance and restore intent messaging before Nostr/backup recovery paths execute.
- **Maintenance UX polish:**
    - maintenance screens now include more explicit operator guidance instead of relying only on toast notifications.
    - relay deletion now mirrors the safer confirmation style used elsewhere in v3.
    - profile/security maintenance screens now surface clearer success and failure summaries in-screen.
    - maintenance screens now share stronger visual hierarchy: bordered intro cards, status panels, and more consistent action-row styling.
    - shared maintenance-screen styling/status helpers now reduce drift across profile, security, pubkey, and relay flows.
    - maintenance screens now also share custom footer strips, removing the remaining mixed use of default Textual footer chrome.
- **Default UI status alignment:**
    - `seedpass` now launches TUI v3 by default.
    - v3 onboarding now owns unlock/create/recover/restore flows inside the app.
- **Inspector UX:**
    - lower inspector now stays collapsed until an entry is selected.
    - close button clears selection and collapses the lower pane again.
- **Context-aware actions:**
    - Action bar now advertises only actions that are meaningful for the selected entry kind.
    - Removed misleading generic QR/reveal hints from entry kinds that do not use them.

- **Secure Data Parity:**
    - Completed `_resolve_sensitive_payload` for SSH, PGP, Nostr, Key-Value, and Documents.
    - Updated `derive_pgp_key` and API to support armored PGP Public Key retrieval/copying.
    - Aligned copy/reveal semantics with mockup hints (e.g., SSH/PGP copy Pub by default).
- **Managed Sessions:**
    - Added `action_managed_load` (`m`) and `action_managed_exit` (`Shift+M`) to v3 with mock service support.
    - Wired `ml` and `mx` commands to the palette.
    - Extended `SeedPlusScreen` to manage accurate sub-account derivation correctly.
    - Added fully functioning dynamic breadcrumb UI via `BrandFingerprint` and `active_breadcrumb`.
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

## 6. Progress Log (2026-03-06)

### Completed in this session
- **Main grid reliability:**
  - fixed v3 main-grid keyboard navigation by restoring focus ownership to `#entry-data-table` on workspace mount
  - closing the command palette now restores focus to the main grid instead of leaving focus on a hidden input
  - added focused regression coverage for default grid focus and post-palette keyboard navigation
- **Search graph navigation baseline:**
  - added `SearchService.linked_neighbors(...)` for deterministic incoming/outgoing link traversal
  - added `SearchService.relation_summary(...)` for grouped relation counts
  - v3 inspector now includes a linked-items panel with direct open-entry actions
- **Grid control hardening:**
  - v3 grid now persists the active search query across refresh/filter/sort changes
  - added explicit in-app filter, search-mode, archived, and sort controls on the main grid surface
  - palette command surface now includes `sort <...>` and routes search-mode changes through app actions for one consistent control path

### Validation evidence
- `pytest -q src/tests/test_tui_v3_smoke.py src/tests/test_tui_v3_parity.py src/tests/test_core_api_services.py` -> `107 passed`
