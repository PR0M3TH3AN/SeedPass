# Memory Update (2026-03-01)

## Nostr backup failure observability
- `handle_post_to_nostr()` previously printed only a generic `❌ Sync failed…` when `sync_vault()` returned `None`, even if `nostr_client.last_error` had useful detail.
- `PasswordManager.sync_vault_async()` swallowed exceptions and returned `None` without reliably setting `nostr_client.last_error`, making root-cause diagnosis hard from CLI.

## Changes made
- Updated `sync_vault_async()` to copy exception text into `nostr_client.last_error` before returning `None`.
- Updated `handle_post_to_nostr()` to include `nostr_client.last_error` in user-visible failure output and log line when available.
- Added regression tests:
  - `test_handle_post_failure_shows_nostr_error`
  - `test_sync_vault_sets_last_error_on_exception`

## Testing note
- Could not run pytest in this environment because `pytest` is not installed (`python3 -m pytest` -> `No module named pytest`).

## Nostr namespace reset workflow
- Added Nostr Settings menu actions for profile-scoped reset operations:
  - `8. Reset Nostr sync state` clears `manifest_id`, `delta_since`, and `last_sync_ts` while preserving `nostr_account_idx`.
  - `9. Start fresh Nostr namespace (new key index)` increments `nostr_account_idx`, clears sync metadata, and reinitializes the Nostr client when available.
- This provides a first-class path for users who want to ignore legacy Nostr history and publish/retrieve only new data under current deterministic behavior.
- Added tests for both handlers and menu dispatch to prevent regressions.

## Documentation updates for Nostr reset workflow
- Added `docs/nostr_namespace_reset.md` documenting menu options `8` (reset sync state) and `9` (start fresh namespace), plus validation steps for robust publish/restore.
- Linked the new guide from `docs/nostr_setup.md`, `docs/README.md`, and root `README.md`.
- Exposed the guide in website docs navigation via `landing/docs.html` (`Nostr Namespace Reset`).

## Nostr sync failure after namespace increment
- Root-cause pattern: when profile `offline_mode` is enabled, `sync_vault_async()` exits early and previously returned `None` without a helpful message, so UI showed only `❌ Sync failed…`.
- Fixes:
  - `PasswordManager.sync_vault_async()` now sets `nostr_client.last_error` for early-return cases (`offline_mode`, missing encrypted index, and missing publish result).
  - `main.handle_post_to_nostr()` now explicitly reports offline mode when no detailed error is present.
- Regression tests added:
  - `src/tests/test_post_sync_messages.py::test_handle_post_failure_offline_mode_message`
  - `src/tests/test_background_vault_sync_paths.py::test_sync_vault_async_sets_offline_error`
- Verified with local venv:
  - `./.venv/bin/pytest -q src/tests/test_post_sync_messages.py`
  - `./.venv/bin/pytest -q src/tests/test_background_vault_sync_paths.py`

## Entry model expansion: document kind + universal date fields
- Added a new `document` entry kind across core enum, TUI, API, CLI, and agent secret resolution.
- Added universal `date_added` and `date_modified` fields for all entry kinds.
  - Creation now sets both fields.
  - Modification preserves `date_added` and updates `date_modified`.
  - Legacy entries are normalized in `_load_index()` by deriving date fields from `modified_ts`/`updated`.
- TUI now supports `Document` creation via a built-in line editor with basic commands (`p`, `a`, `i <n>`, `e <n>`, `d <n>`, `w`, `q`).
- Added document-specific display and edit flows in manager/display services.

## Sync/policy compatibility notes
- Updated deterministic merge kind matrix to include document fields (`content`, `file_type`) for equal-timestamp backfill behavior.
- Agent defaults now include `document` in non-private allow-kinds, and agent secret resolution returns document content for `document` entries.

## Tests and docs
- Added/updated tests for:
  - document entry roundtrip and CLI add command
  - universal date field presence/update semantics across all entry kinds
  - API create/modify behavior for `document`
  - large document Nostr sync roundtrip
- Added `docs/entry_types.md` and updated README/docs index and sync conflict docs.
- Verified with:
  - `./.venv/bin/pytest -q src/tests/test_cli_entry_add_commands.py src/tests/test_entry_add.py src/tests/test_entry_types_roundtrip.py src/tests/test_modify_entry_validation.py src/tests/test_api.py src/tests/test_api_new_endpoints.py src/tests/test_full_sync_roundtrip.py`
  - Result: `141 passed`.

## Document file import/export workflows
- Added document file I/O at core layer:
  - `EntryManager.import_document_file(path, ...)`
  - `EntryManager.export_document_file(index, output_path=None, overwrite=False)`
- Added TUI support:
  - `Add Entry > Document` now supports `New Document` and `Import Document File`.
  - Document entry actions now include `Export Document to File`.
- Added automation surfaces:
  - CLI: `entry import-document`, `entry export-document`
  - API: `POST /api/v1/entry/document/import`, `POST /api/v1/entry/{id}/document/export`
- Regression coverage added for core file roundtrip, CLI commands, and API endpoints.

## Agent document import/export commands
- Added dedicated agent CLI commands:
  - `seedpass agent document-import --file <path>`
  - `seedpass agent document-export <query>` (or `--entry-id`)
- Enforcement model for both commands:
  - Requires `--fingerprint` and non-interactive auth broker password resolution.
  - Denies unless policy `allow_export_import` is enabled.
  - Denies unless `document` kind is policy-allowed (`allow_kinds` / kind export check).
  - Supports scoped token enforcement with operation scopes (`import` for import, `export` for export).
  - Export honors approval gates when policy requires `export` approval.
  - Emits structured JSON responses and append-only audit events for granted/denied outcomes.
- Discovery updates:
  - Added `document_io` command hints to `agent bootstrap-context` payload.
  - Added `document_io` section to `seedpass capabilities --format json` security features.
- Added CLI tests for:
  - token-scoped agent document import success path
  - token-scoped agent document export success path
  - bootstrap context includes document command hints
- Environment note: could not run pytest in this shell because `pytest` is unavailable (`python3 -m pytest` reports module missing).

## Test environment note (2026-03-01)
- Repo `.venv` already had `pytest` and `typer`; upgraded to `pytest 9.0.2` and `typer 0.24.1`.
- New agent document I/O tests initially failed due mocked policy normalization (empty `rules` caused normalized `allow_kinds` to become empty).
- Fixed tests by adding explicit allow rule for `document` in mocked policies.
- Verification run:
  - `.venv/bin/pytest -q src/tests/test_document_file_io.py src/tests/test_cli_entry_add_commands.py src/tests/test_api_new_endpoints.py src/tests/test_entry_types_roundtrip.py src/tests/test_full_sync_roundtrip.py src/tests/test_cli_agent_mode.py`
  - Result: `150 passed`.

## Full-suite regression repair after document rollout
- Ran full suite after enabling agent document I/O and found 12 regressions (mostly stale tests).
- Fixed regressions by updating tests for:
  - new document add-menu option/mocks (`handle_add_document`),
  - expanded `EntryService.modify_entry` kwargs,
  - universal `date_added`/`date_modified` and `custom_fields` fields in entry expectations,
  - `list_entries(sort_by="updated")` relying on `modified_ts`,
  - legacy decrypt fallback monkeypatches to accept `salt` argument and revised iteration-call expectations.
- Verification: `.venv/bin/pytest -q src/tests` => `891 passed, 11 skipped`.

## Knowledge graph links integration (entry relationships)
- Added first-class graph edges to every entry via shared `links` field (list of `{target_id, relation, note}`).
- Implemented core link operations in `EntryManager`:
  - `add_link(entry_id, target_id, relation, note)`
  - `remove_link(entry_id, target_id, relation=None)`
  - `get_links(entry_id)` with resolved target label/kind.
- Added normalization/defaulting for `links` in index load path, including cache-return normalization to prevent stale in-memory schemas.
- Extended `modify_entry(..., links=...)` to allow full links replacement with validation.
- Search now matches link metadata (`relation`, `note`) and linked target labels, enabling graph-style discovery from existing index scans.
- Sync conflict equal-timestamp union now includes `links` alongside `tags` and `custom_fields` for deterministic convergence.
- Added API endpoints:
  - `GET /api/v1/entry/{id}/links`
  - `POST /api/v1/entry/{id}/links`
  - `DELETE /api/v1/entry/{id}/links`
  and `PUT /api/v1/entry/{id}` now accepts `links`.
- Added CLI graph commands:
  - `seedpass entry link-add`
  - `seedpass entry links`
  - `seedpass entry link-remove`
  plus `entry modify --links-json`.
- Documentation updated in `README.md`, `docs/entry_types.md`, and `docs/sync_conflict_contract.md`.
- Validation:
  - Focused suite: `140 passed`
  - Full suite: `895 passed, 11 skipped`.

## Website/docs refresh for graph features
- Added dedicated graph docs page: `docs/entry_graph.md`.
- Updated docs indexes/navigation:
  - `docs/README.md` now lists `entry_graph.md`.
  - `landing/docs.html` sidebar now includes `Entry Graph`.
- Updated landing page feature cards (`landing/index.html`) to highlight:
  - Entry Graph Links
  - Graph-Aware Entry Ops CLI commands
- Updated docs cross-links:
  - `docs/entry_types.md` points to `docs/entry_graph.md`.
- Updated README feature bullets to include Entry Graph Links.

## Landing graph example + help-hint refresh
- Added a visual graph snippet block to landing architecture section (`landing/index.html`) showing linked entries and graph query behavior.
- Styled graph snippet in `landing/style.css` (`.graph-snippet`) to match the terminal UI aesthetic.
- Expanded help/discovery surfaces for users and agents:
  - `seedpass capabilities` now includes a `knowledge_graph` security feature block with CLI/API graph commands and sync/search behavior.
  - Capabilities API discovery now lists `/api/v1/entry/{id}/links`.
  - Capabilities text output now explicitly mentions graph links and document workflows.
  - Capabilities `help_hints` now include graph/document command pointers.
  - `agent bootstrap-context` now includes `commands.knowledge_graph` hints.
  - Root CLI help string now mentions document I/O and entry graph links.
- Verification:
  - `.venv/bin/pytest -q src/tests/test_typer_cli.py -k "capabilities_text or capabilities_json" src/tests/test_cli_agent_mode.py -k "bootstrap_context"`
  - Result: `2 passed`.

## TUI v2 scaffold kickoff on beta
- Added `docs/tui_v2_plan.md` with phased migration plan, risk controls, and testing strategy for Textual-based TUI v2.
- Added experimental CLI command `seedpass tui2` and diagnostics mode `seedpass tui2 --check`.
- Added new runtime-check/launcher scaffold package at `src/seedpass/tui_v2/`.
- Updated discoverability/docs surfaces:
  - `docs/README.md` includes `tui_v2_plan.md`
  - `landing/docs.html` includes `TUI v2 Plan`
  - `README.md` discovery snippet includes `seedpass tui2 --check`
  - `capabilities` root commands/help hints include `tui2`
- Validation:
  - `py_compile` for updated modules
  - `pytest` capabilities tests (`2 passed`)
  - `.venv` smoke run confirms `seedpass tui2 --check` emits runtime diagnostics.
- 2026-03-01: TUI v2 phase 1 moved from placeholder to functional read-only Textual shell. `seedpass tui2` now passes a lazy `entry_service_factory` so vault/service init only happens when Textual is actually available, preventing unnecessary prompts on unavailable runtimes.
- Added focused CLI tests in `src/tests/test_typer_cli.py` for `tui2 --check`, unavailable + no fallback exit path, and legacy fallback fingerprint forwarding.
- 2026-03-01: TUI v2 phase 2 slice added in `seedpass/tui_v2/app.py`: archive/restore action (`a`), document editor mode (`e`) with save/cancel (`Ctrl+S`/`Esc`), and a persistent status line for operation feedback.
- Document editor uses `TextArea` when available and falls back to single-line input if unavailable, keeping runtime compatibility across Textual versions.
- 2026-03-01: TUI v2 gained `Ctrl+P` command palette with command parsing (`help`, `open`, `search`, `filter`, `archive/restore`, `edit-doc/save-doc/cancel-edit`, `link-add`, `link-rm`, `refresh`).
- Added a graph links panel in the right view that renders current entry links via `EntryService.get_links` and updates after palette link mutations.
- 2026-03-01: TUI v2 graph navigation expanded with relation-aware link filtering (`l` or `link-filter`) and quick neighbor traversal (`[`/`]` to change selected link, `o` or `link-open` to jump to target entry).
- Link panel now tracks selection state and displays active relation filter + selected link position to support KB-style navigation in large graphs.
- 2026-03-01: Phase 4 kickoff added `docs/tui_v2_parity_checklist.md` and linked it in docs indexes (`docs/README.md`, `landing/docs.html`) to track legacy-vs-v2 cutover readiness.
- TUI v2 large-vault UX/perf pass: entry list pagination (200/page, `p`/`n`, palette `page-next/page-prev/page <n>`) and document detail preview truncation (`content_truncated`) to avoid rendering extremely large payloads in the detail pane.
- 2026-03-01: TUI v2 error/recovery pass added unified failure recording (`_record_failure`) and retry workflow (`x` key + palette `retry`) across init/search/select/link/save/archive paths.
- Recovery hints are now included in status messages (for example, "Press 'x' to retry") and Phase 4 docs mark error/recovery flow work complete.
- 2026-03-01: Added `docs/tui_v2_cutover_decision.md` with explicit recommendation to keep legacy default for next release, required cutover gates, staged rollout, and rollback plan for switching `seedpass` default to TUI v2.
- Updated phase tracking docs to mark the cutover timing decision item complete and linked the memo in docs indexes.
- 2026-03-01: Began cutover-gate automation by extracting testable TUI v2 helpers (`parse_palette_command`, `pagination_window`, `truncate_entry_for_display`) from `tui_v2/app.py`.
- Added `src/tests/test_tui_v2_helpers.py` with coverage for palette parsing edge cases, pagination normalization, and large-vault pagination smoke sizes up to 50k rows.
- 2026-03-01: Added Textual interaction tests in `src/tests/test_tui_v2_textual_interactions.py` for pagination/search, document edit+save, link add/remove + neighbor open, and retry-after-failure.
- Introduced a test hook in `launch_tui2(..., app_hook=...)` so tests can capture and pilot the Textual app instance without starting a live terminal run.
- 2026-03-01: Added CI-like large-vault validation with explicit thresholds in `src/tests/test_tui_v2_large_vault_validation.py` (10k rows standard, 50k rows under `--stress`).
- Added docs `docs/tui_v2_large_vault_validation.md` with exact commands and budgets; parity checklist now marks large-vault CI-like validation complete.
- 2026-03-01: Added deterministic TUI v2 parity scenarios across entry kinds in `src/tests/test_tui_v2_parity_scenarios.py` (kind filters, archive/restore roundtrip, non-document edit guard).
- Completed help/docs alignment gate: updated `seedpass tui2` help text, capabilities hints for keybindings/palette (`Ctrl+P`, `p/n`, `x`), and docs discoverability commands (`seedpass tui2 --help/--check`).
- 2026-03-01: Switched default root CLI interactive routing to TUI v2 in `seedpass.cli.main` (when no subcommand), with automatic legacy fallback when Textual runtime is unavailable.
- Added explicit one-release override flag `--legacy-tui` and updated test coverage (`test_typer_cli.py`) for default TUI v2 launch, forced legacy path, and root fallback behavior.
- 2026-03-01: UX pass for TUI v2 added help overlay (`?`), quick jump input (`j`), pane focus switching (`1/2/3`) with visual focus borders, mode-tagged status line, and an activity log panel of recent actions.
- Added document dirty-state UX improvements (`Edit mode [*]` marker, no-op save guard) and updated Textual interaction/parity tests for Textual 8-compatible action-driven control paths.
- 2026-03-01: Visual polish pass for TUI v2 updated panel styling hierarchy (stronger status/pane contrast), refined left-panel summaries, improved help overlay readability, and added labeled headers for entry/detail and links sections.
- UI copy now emphasizes current selection/filter context while keeping deterministic action affordances unchanged; full TUI-focused test slice remains green.
