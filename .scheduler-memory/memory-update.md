# Memory Update (2026-03-05)

## TUI v3 onboarding parity
- TUI v3 now owns profile selection, unlock, add-new profile, blank-index recovery, Nostr restore, and local-backup restore flows inside the app, using non-interactive bootstrap helpers in `PasswordManager` instead of CLI-side prompts.
- `docs/dev_control_center.md` now reflects that the Index0 track is beyond spec-only status: Phase 1 foundation is partially implemented and the next deferred slice is event-emission hooks.
- Remaining onboarding parity gap is mostly UX fidelity: a true word-by-word seed entry experience and richer restore guidance, not missing core bootstrapping capability.

## TUI v3 inspector behavior
- The v3 inspector should stay fully collapsed until the user explicitly selects an entry; Textual `DataTable` can emit an automatic initial `RowHighlighted` event on mount, so that first highlight must be suppressed or it will look like the inspector auto-opens on startup.
- Action-bar hotkey labels should avoid markup like `[b][S][/b]ettings`; Rich/Textual interprets `[S]` as markup, which drops the visible first letter. Use `[b]S[/b]ettings` instead.

## TUI v3 parity/docs alignment
- `docs/dev_control_center.md` had drifted back to a TUI v2-first execution order even though `seedpass` now launches TUI v3 by default; the control center should treat v3 as the active UI track and v2 as reference-only unless explicitly reactivated.
- The v3 plan previously overstated lifecycle parity; delete-entry workflow is still missing from the v3 shell and should remain an explicit open item until it is actually wired and tested.
- The v3 action strip should be kind-aware instead of generic. Good defaults: documents/notes should not advertise QR or reveal, seeds/managed accounts should show load, and export should only appear for kinds with a real export path.

## TUI v3 delete workflow
- The core delete path already existed in `entry_management`, but the UI-facing thread-safe `EntryService` wrapper in `core/api.py` did not expose it. V3 delete support required adding that wrapper method rather than inventing a separate code path.
- For v3, delete fits the same safety model as other high-risk actions: first press shows an in-board confirmation prompt, second `d` within 8 seconds executes the delete, then clears selection so the collapsed-inspector behavior remains consistent.

## TUI modularity pattern
- The current UI modularity is still healthy when new capabilities are added through `core/api.py` service wrappers first, then surfaced in TUI v3 actions/screens. This keeps future GUIs from depending on `PasswordManager` internals or Textual-specific state.
- Recent example: `npub`, `nostr-reset-sync-state`, and `nostr-fresh-namespace` were already available in `NostrService`, so v3 could add palette/screen affordances without pushing new UI logic into core.

## TUI v3 security maintenance flows
- `change-password` and `backup-parent-seed` are good examples of future-GUI-safe carryover: keep input collection in dedicated v3 screens, then submit typed request models to `VaultService` instead of embedding vault mutation logic in the UI.
- The settings screen is currently a useful discoverability hub for these maintenance commands even when the actual mutation happens in separate screens; that pattern scales better than overloading the main workspace.

## TUI v3 profile maintenance
- Profile switch/remove belongs in a dedicated maintenance screen rather than the startup flow only. Using `ProfileService` request models keeps this future-GUI-safe and avoids direct UI coupling to fingerprint-manager internals.
- As more maintenance screens land, app-level refresh helpers cannot assume the main workspace is always the active screen; refresh paths should degrade gracefully when called from modal or utility screens.
- Maintenance-flow polish matters as much as raw parity: profile lists should prefer display labels over raw fingerprints when available, and destructive actions like profile removal should require an explicit second action inside the screen rather than firing on the first button press.
- Restore/import flows benefit from mode-specific guidance text before submit; even simple status hints reduce operator error on Nostr vs local-backup recovery paths.

## Maintenance-screen UX pattern
- For v3 maintenance utilities, good UX defaults are: an intro block explaining the operation, an in-screen status area for progress/errors, and a confirmation step for destructive actions. Toasts alone are not enough once these screens become part of the main product flow.
- Relay management benefits from the same confirmation posture as entry/profile deletion; consistency matters more than treating relay removal as a special case.
- Once those patterns are in place, the next level of polish is visual consistency: heavy outer cards, bordered intro/status sections, and consistent action-row/button treatment make maintenance screens feel like part of the same product instead of disconnected utility dialogs.
- A shared maintenance-screen helper (`screens/maintenance.py`) is now the right place for common CSS/status phrasing; future maintenance flows should use it instead of copying screen-local variants.
- Footer chrome is part of that consistency too; custom black maintenance footers fit the SeedPass shell better than the default Textual `Footer` widget for these screens.

## 2026-03-05 index0 emission slice
- Implemented `index0` CRUD/link event emission in `src/seedpass/core/entry_management.py` using new shared helpers in `src/seedpass/core/index0.py`.
- `index0` now appends deterministic events for create/modify/archive/restore/delete and link add/remove, updates per-writer heads, and derives hierarchy-aware `scope_path` from the active fingerprint directory (`seed/<root>` or `seed/<root>/managed/<child>`).
- Added focused regression coverage in `src/tests/test_index0_events.py`.
- Updated roadmap docs so the next `index0` slice is checkpoints/compaction plus canonical view rebuilders and manifest publication, not CRUD/link emission.

## 2026-03-05 index0 checkpoint and manifest slice
- Added deterministic daily checkpoint rebuild in `src/seedpass/core/index0.py`, with bounded retention per writer and manifest export metadata (`checkpoint_ids`, `checkpoint_hashes`, `stream_heads`).
- `Vault.save_index()` now compacts `_system.index0` before encrypting, so synced payloads carry rebuilt checkpoints consistently.
- `PasswordManager.sync_vault_async()` now computes/persists compacted `index0` state before publish and passes manifest atlas metadata to the Nostr snapshot publisher, keeping manifest validation data aligned with the encrypted payload.
- Added focused regressions in `src/tests/test_index0_checkpoints.py`; next `index0` slice is canonical view rebuilders/read helpers, not checkpoint generation.

## 2026-03-05 index0 canonical views slice
- Added deterministic synced canonical views in `src/seedpass/core/index0.py`: `children_of`, `counts_by_kind`, and `recent_activity`.
- Canonical view rebuild now runs inside `compact_index0_payload(...)` alongside checkpoint rebuild; `Vault.save_index()` passes the active fingerprint path so scope-aware views can be rebuilt even for sparse/legacy payloads.
- Added lightweight read helpers `list_canonical_views(...)` and `get_canonical_view(...)` for later service/UI consumers.
- Focused coverage lives in `src/tests/test_index0_views.py`; next `index0` work should be atlas read services and v3/UI consumers, not more storage plumbing.

## 2026-03-05 index0 atlas consumer slice
- Added `AtlasService` in `src/seedpass/core/api.py` to expose `index0` status, view lookup, view listing, and a combined `wayfinder()` payload through the same service boundary used by TUI/GUI clients.
- Added the first v3 atlas consumer in `src/seedpass/tui_v3/screens/atlas.py` and wired `atlas` / `wayfinder` palette commands in `src/seedpass/tui_v3/app.py`.
- The right next `index0` step is deeper v3 integration (main shell wayfinder/stateful landing surfaces) and agent-facing atlas workflows, not more low-level storage plumbing.

## 2026-03-05 index0 embedded v3 workspace slice
- Added `AtlasStrip` in `src/seedpass/tui_v3/widgets/header.py` and mounted it in the main v3 workspace so atlas wayfinder data is visible even with no active selection.
- The first embedded shell integration is intentionally light: scope path, top counts, and most recent event. The next `index0` UI step should be richer navigation actions from this strip or a docked wayfinder panel, not more exposure-only widgets.

## 2026-03-05 index0 actionable v3 wayfinder slice
- The v3 atlas screen in `src/seedpass/tui_v3/screens/atlas.py` now supports direct entry jumps and quick kind-filter jumps, making `index0` wayfinder data actionable instead of read-only.
- Added `w` as a first-class v3 binding for the wayfinder and surfaced it in the action bar.
- The next meaningful `index0` step is not more exposure widgets; it is deeper search/navigation handoff and agent-facing atlas workflows built on the existing `AtlasService`.

## 2026-03-05 atlas/search/graph planning slice
- Added `docs/atlas_search_graph_integration_plan_2026-03-05.md` to define how `index0`, tags, links, and local semantic search should integrate.
- The agreed next implementation target is `SearchService` plus unified result schema, deterministic filters/sorting, and linked-item navigation, not more foundational `index0` storage work.
- Updated central docs so current shipped accomplishments are recorded consistently: v3 default UI, semantic index integration, canonical tags/links, and `index0` foundations plus current v3 atlas consumers.

## 2026-03-05 unified search service slice
- Added `SearchService` in `src/seedpass/core/api.py` as the new service-layer search contract above raw entry search and local semantic search.
- The normalized result payload now carries score breakdowns, match reasons, safe excerpts, tags, linked-hit summaries, archived state, and scope path so TUI/GUI clients do not need to reconstruct search metadata themselves.
- TUI v3 grid should prefer `SearchService` instead of branching directly between `EntryService` and `SemanticIndexService`; keep semantic search as an implementation detail behind the unified service boundary.
- The next practical search/graph slice is linked-neighbor APIs plus explicit v3 sort/filter controls, not another round of search-contract work.
- `docs/dev_control_center.md` should treat that linked-navigation + explicit sort/filter slice as the immediate next step so future runs do not fall back to older TUI carryover wording.

## 2026-03-05 Nostr communications research
- Added `docs/nostr_comms_reference_and_future_capability_2026-03-05.md` as a future-capability reference for DMs and team/community chat.
- SeedPass-specific protocol direction recorded there: prefer `NIP-17` + `NIP-44` + `NIP-59` for private managed DMs, evaluate `NIP-29` for institutional group chat, and treat `NIP-28` / `NIP-72` as public/community-oriented layers.
- The control center now links this as a future capability track and explicitly keeps it behind current v3/search/index0/security priorities.
