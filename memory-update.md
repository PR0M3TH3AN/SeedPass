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
- 2026-03-01: Reduced TUI v2 status noise by deduplicating repeated status messages before appending to status bar/activity log.
- Verified critical coverage gate against existing full coverage artifact (`artifacts/coverage/coverage.json`): all default threshold modules pass (main/core manager/core encryption/core migrations).

## 2026-03-01 Determinism test infrastructure hardening
- Added a dedicated determinism lane with `scripts/run_determinism_tests.sh` and wired `scripts/run_ci_tests.sh` to run it by default (`DETERMINISM_GATE=1`, disable with `DETERMINISM_GATE=0`).
- Added pytest marker support for determinism (`pyproject.toml`, `src/tests/conftest.py`) and a `--determinism-only` selector that skips non-determinism tests.
- Expanded deterministic regression vectors in `src/tests/test_deterministic_artifact_regression.py`:
  - pinned entropy-stream SHA-256 vectors for indexes `0,1,352,1024`
  - pinned password outputs for policy variants (default, safe specials, no specials, exclude ambiguous, restricted special charset)
- Marked existing deterministic suites so they run in the determinism lane: password helpers/policy plus seed, SSH, PGP, and Nostr determinism tests.
- Verified determinism lane now executes 23 focused tests and fails fast on derivation drift.

## 2026-03-01 Determinism gates + cross-process + size-tier sync tests
- Added `scripts/check_determinism_suite.py` and wired it into `scripts/run_determinism_tests.sh`.
- Determinism gate now enforces both a minimum test count (`DETERMINISM_MIN_TESTS`, default 25) and required determinism files, preventing accidental suite erosion.
- Added unit tests for determinism gate parser logic in `src/tests/test_check_determinism_suite.py`.
- Added cross-process determinism regression in `src/tests/test_cross_process_determinism.py`; derives artifacts in separate Python processes and asserts exact JSON identity.
- Expanded size-tier sync integrity coverage:
  - `src/tests/test_document_file_io.py` includes large document import/export and portable backup restore invariance checks (hash/equality).
  - `src/tests/test_full_sync_roundtrip.py` includes parameterized large document Nostr sync roundtrip with content hash checks.
  - `src/tests/test_nostr_snapshot.py` includes chunk hash and gzip roundtrip integrity across multiple payload size tiers.
- Current determinism lane status after updates: 43 passed, 916 skipped.

## 2026-03-01 TUI v2 agent harness + deep coverage expansion
- Added `scripts/ai_tui2_agent_test.py` as a deterministic agent-style TUI v2 harness using Textual pilot mode; emits timestamped JSON reports in `artifacts/agent_tui2_test/`.
- Added test/process documentation: `docs/agent_test_format.md` with repeatable commands for TUI v2, legacy interactive harness, CLI/CUI, API, and determinism gate runs.
- Fixed legacy harness invalid-input regression after Document type addition: in `scripts/ai_tui_agent_test.py`, Add Entry invalid choice now uses `99` instead of `9`.
- Added `src/tests/test_tui_v2_action_matrix.py` to exercise broad TUI v2 action and palette paths (including guards/failure/retry/event handlers).
- Fixed a real TUI v2 help-overlay bug in `src/seedpass/tui_v2/app.py` where `[/]` text triggered Textual markup parsing errors (`MarkupError`).
- Latest TUI v2 focused coverage run:
  - Command: test helper/interactions/parity/large-vault/action-matrix suites with `--cov=seedpass.tui_v2.app`
  - Result: 25 passed, 2 skipped
  - Coverage: 86% for `src/seedpass/tui_v2/app.py` (up from ~57%).
- Harness validation results:
  - `scripts/ai_tui2_agent_test.py --scenario extended`: passed
  - `scripts/ai_tui_agent_test.py --scenario core`: passed

## 2026-03-01 Installer + TUI v2 preflight fix (gray-screen mitigation)
- Root cause found for "blank/gray screen" reports: TUI v2 was initializing `PasswordManager` inside Textual mount via `entry_service_factory`, so password/setup prompts could occur behind the Textual screen and appear as a frozen UI.
- Updated `src/seedpass/cli/__init__.py` to pre-initialize entry service before launching Textual (`_prime_tui2_service`), then pass the ready service into `launch_tui2`.
- Added explicit fallback/error behavior:
  - default `seedpass`: preflight failures now fall back to legacy TUI with details.
  - `seedpass tui2 --no-fallback-legacy`: preflight failures now return exit code 1 with a clear error.
- Updated installer `scripts/install.sh` to run `seedpass tui2 --check` after install and warn when Textual runtime is unavailable, plus print a legacy fallback hint for users seeing blank/gray startup.
- Added regression coverage in `src/tests/test_typer_cli.py` for preflight behavior and adapted existing TUI launch tests to mock preflight service creation.

## 2026-03-01 TUI v2 parity slice: reveal + QR integration
- Added Textual TUI v2 sensitive-data actions:
  - Keybindings: `v` reveal selected secret, `g` show QR.
  - Palette commands: `reveal`, `qr`.
- Implemented reveal support for entry kinds: `password`, `seed`, `managed_account`, `totp`.
- Implemented QR rendering in-app (ASCII QR panel) for:
  - TOTP (`otpauth://` payload)
  - Seed / managed account seed (SeedQR digit payload)
- Added a dedicated `#secret-detail` panel in the right pane and reset-on-selection behavior to avoid stale secret display.
- Extended core `EntryService` API with deterministic seed retrieval methods used by TUI v2:
  - `get_seed_phrase(entry_id)`
  - `get_managed_account_seed(entry_id)`
- Added/updated tests for helper QR rendering, TUI reveal/QR workflows, and service wrappers; targeted suite passed.

## 2026-03-01 TUI v2 parity slice: SSH/PGP/Nostr + secret mode behavior
- Extended TUI v2 sensitive reveal support to additional kinds: `ssh`, `pgp`, and `nostr`.
- Added legacy-aligned confirmation semantics in TUI v2:
  - `reveal confirm` required for high-risk reveals (`seed`, `managed_account`, `ssh`, `pgp`).
  - `qr private confirm` required for Nostr private-key QR rendering.
- Added `qr` mode parsing (`qr [public|private] [confirm]`) and retained default safe behavior (`public` for Nostr).
- Integrated secret-mode behavior into TUI reveal flow:
  - when secret mode is enabled, reveal copies sensitive value to clipboard and avoids on-screen plaintext output for that reveal.
- Expanded `EntryService` API for TUI parity and safe abstraction from manager internals:
  - `get_ssh_key_pair`, `get_pgp_key`, `get_nostr_key_pair`
  - `get_secret_mode_enabled`, `get_clipboard_clear_delay`, `copy_to_clipboard`
- Added/updated tests covering confirmation-gated flows, Nostr private QR confirmation, and secret-mode clipboard behavior.

## 2026-03-01 TUI v2 visual alignment with landing page
- Updated Textual TUI v2 default styling to mirror landing-page palette tokens:
  - background: `#080a0c` / panel: `#0d1114`
  - primary text: `#97b8a6` / bright text: `#daf2e5`
  - accent borders/focus: `#58f29d`, `#2abf75`, `#274533`, `#1a3024`
- Styled Header/Footer/Input/ListView/ListItem focus/selection states to reduce default Textual blue and align with SeedPass mint-green terminal aesthetic.
- Added website-style icon semantics into TUI copy and sensitive panel titles (key/mobile/network/lock/bolt/document/users/seed mappings) to improve visual continuity between landing and app.

## 2026-03-01 Legacy launch ergonomics
- Added explicit CLI command `seedpass legacy` to launch the legacy interactive TUI directly, in addition to existing global flag `--legacy-tui`.
- Refactored legacy launch path through a shared helper in `seedpass.cli` so root fallback, `--legacy-tui`, `tui2` fallback, and `legacy` command all use consistent behavior and fingerprint forwarding.
- Added CLI regression tests for `seedpass legacy` with and without `--fingerprint`.
- Updated discoverability docs in `README.md` and `docs/README.md`.

## 2026-03-01 KB scale stress coverage + launch docs
- Added `src/tests/test_kb_scale_stress.py` for large-index KB validation:
  - sort/tag/search across `10k` entries (and `100k` with `--stress`)
  - high-degree graph link validation (`1k` edges standard, `5k` edges stress)
- Added `src/tests/test_tui_v2_kb_scale_stress.py` for Textual large-index interaction validation:
  - pagination/navigation/search/filter behavior at `10k` rows standard and `50k` rows under `--stress`
- Added docs `docs/kb_scale_validation.md` with exact commands for standard and `--stress` runs.
- Updated launch documentation to clearly show all interactive launch modes:
  - default (`seedpass`), explicit v2 (`seedpass tui2`), and legacy (`seedpass legacy` / `seedpass --legacy-tui`).

## 2026-03-01 TUI v2 parity backlog prioritization
- TORCH latest daily/weekly memory snapshots are mostly scheduler metadata; TUI parity priorities should continue to be driven by `docs/tui_v2_plan.md`, `docs/tui_v2_parity_checklist.md`, and direct legacy-vs-v2 code diff.
- Highest-impact remaining parity gaps identified:
  1) Add-entry workflows for all kinds in TUI v2
  2) Retrieve/action parity (notes/custom fields/tags/edit field-level variants/document export/QR submenus)
  3) 2FA codes live board parity with timer + secret-mode clipboard behavior
  4) Settings/profile/nostr operational parity in TUI v2
  5) CI smoke gate for `seedpass tui2 --check` still marked open in plan

## 2026-03-01 TUI v2 parity tracking + Phase A add-entry slice
- Added a dedicated continuation tracker `docs/tui_v2_parity_backlog.md` and linked it from:
  - `docs/tui_v2_plan.md`
  - `docs/tui_v2_parity_checklist.md`
  - `docs/README.md`
- Landed TUI v2 command-palette add-entry flows in `src/seedpass/tui_v2/app.py`:
  - `add-password <label> <length> [username] [url]`
  - `add-totp <label> [period] [digits] [secret]`
  - `add-key-value <label> <key> <value>`
  - `add-document <label> <file_type> <content>`
- Added usage validation and post-create behavior:
  - strict argument/typing checks with status feedback
  - refresh + selection focus to created entry (or nearest match for TOTP)
  - retry wiring through existing `x` recovery path on service failures
- Extended Textual tests:
  - `src/tests/test_tui_v2_textual_interactions.py` now includes add-command success and validation-error scenarios.
  - `src/tests/test_tui_v2_action_matrix.py` test service now implements add methods and exercises add-command guards/success paths.
- Validation run:
  - `.venv/bin/pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py src/tests/test_tui_v2_helpers.py`
  - Result: `24 passed`.
- Updated backlog checkoffs (Phase A): password/TOTP/key-value/document creation + validation/post-create focus are now marked complete; remaining work is SSH/PGP/Nostr/Seed/Managed Account creation flows and downstream parity phases.

## 2026-03-01 TUI v2 parity Phase A completion (remaining add kinds)
- Extended TUI v2 command palette add workflows in `src/seedpass/tui_v2/app.py` for remaining entry kinds:
  - `add-ssh <label> [index]`
  - `add-pgp <label> [index] [key_type] [user_id]`
  - `add-nostr <label> [index]`
  - `add-seed <label> [words] [index]`
  - `add-managed-account <label> [index]`
- Added argument validation and status hints for all new commands, including integer checks for index/words arguments and retry integration on service failures.
- Updated discoverability text in palette/help/filter hints to include the new add command set.
- Expanded test doubles and coverage:
  - `src/tests/test_tui_v2_textual_interactions.py`: success + validation coverage for all add commands (existing and new).
  - `src/tests/test_tui_v2_action_matrix.py`: guard paths and success paths for new add commands.
- Validation run repeated after formatting:
  - `.venv/bin/pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py src/tests/test_tui_v2_helpers.py`
  - Result: `24 passed`.
- Backlog update:
  - `docs/tui_v2_parity_backlog.md` Phase A is now fully checked off.
  - Next priority to start: Phase B retrieve/action parity (notes/custom fields/tags/field-level edits/document export/nostr QR submenu behaviors).

## 2026-03-01 TUI v2 parity Phase B slice: notes/tags/custom fields/document export
- Added retrieve/action parity commands to TUI v2 palette in `src/seedpass/tui_v2/app.py`:
  - `notes-set <text>` / `notes-clear`
  - `tag-add <tag>` / `tag-rm <tag>` / `tags-set <comma-list>` / `tags-clear`
  - `field-add <label> <value> [hidden-token]` / `field-rm <label>`
  - `doc-export [output_path]` (selected document only)
- Introduced helper paths for selected-entry mutation:
  - `_selected_entry_payload()` for reliable selected entry fetch/guarding
  - `_apply_selected_modify(...)` to centralize modify->reload->reselect->retry behavior
- Added/extended tests:
  - `src/tests/test_tui_v2_textual_interactions.py` adds success + validation coverage for notes/tags/custom fields/doc export.
  - `src/tests/test_tui_v2_action_matrix.py` now exercises new command guards and paths.
  - Fake services in both test files now implement `export_document_file(...)`.
- Validation:
  - `.venv/bin/pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py src/tests/test_tui_v2_helpers.py`
  - Result: `26 passed`.
- UI-status formatting note for Textual markup:
  - Bracketed usage strings like `[hidden]`/`[output_path]` get treated as markup and partially disappear in status rendering.
  - Switched those usage strings to plain text `(optional: ...)` format.
- Backlog updates in `docs/tui_v2_parity_backlog.md`:
  - Checked off Phase B items for notes, tags, custom fields, document export, and Nostr public/private QR submenu parity.
  - Remaining Phase B gap: field-level edit parity for non-document kinds.

## 2026-03-01 TUI v2 parity Phase B slice: field-level edits for non-document kinds
- Added palette commands in `src/seedpass/tui_v2/app.py`:
  - `set-field <name> <value>` (alias `field-set`)
  - `clear-field <name>` (alias `field-clear`)
- Implemented kind-aware field edit allowlists and validation:
  - password: `label/notes/username/url/length`
  - totp: `label/notes/period/digits`
  - key_value: `label/notes/key/value`
  - document: `label/notes/file_type/content`
  - other kinds: `label/notes`
- Integer coercion/validation added for `length/period/digits` with explicit status errors.
- Added shared selected-entry modify helpers to keep behavior deterministic and consistent:
  - `_selected_entry_payload()`
  - `_apply_selected_modify(...)`
- Expanded tests:
  - `src/tests/test_tui_v2_textual_interactions.py` adds success + validation tests for set/clear field workflows across password/totp/key_value.
  - `src/tests/test_tui_v2_action_matrix.py` includes command guard and action-path coverage for new commands.
- Validation:
  - `.venv/bin/pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py src/tests/test_tui_v2_helpers.py`
  - Result: `28 passed`.
- Backlog update:
  - `docs/tui_v2_parity_backlog.md` now marks Phase B field-level edit parity complete.
  - Phase B is effectively complete in tracker and next focus should move to Phase C (dedicated 2FA board parity).

## 2026-03-01 TUI v2 parity Phase C: dedicated 2FA board
- Added dedicated 2FA board mode in `src/seedpass/tui_v2/app.py`:
  - keybind: `6` (`action_toggle_totp_board`)
  - palette commands: `2fa-board`, `2fa-hide`, `2fa-refresh`, `2fa-copy <entry_id>`
- Added right-pane board widget `#totp-board` and visibility switching helpers.
- Added live refresh/timer behavior:
  - app interval tick (`set_interval(1.0, _tick_totp_board)`) updates board while visible
  - per-row remaining seconds (`rem`) based on each TOTP period
- Added board display semantics for deterministic/imported split:
  - source column (`det` / `imp`) from `deterministic` flag fallback to secret presence
- Added secret-mode behavior for board:
  - board masks visible codes as `******` when secret mode is enabled
  - `2fa-copy` copies actual code to clipboard and reports clear-delay status
- Updated help/filter/palette discoverability text with new 2FA board commands.
- Test coverage added/expanded:
  - `src/tests/test_tui_v2_textual_interactions.py`:
    - `test_tui2_textual_2fa_board_view_timer_and_copy`
    - `test_tui2_textual_2fa_board_secret_mode_and_validation`
  - `src/tests/test_tui_v2_action_matrix.py` command matrix includes 2FA command guards/actions
- Validation:
  - `.venv/bin/pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py src/tests/test_tui_v2_helpers.py`
  - Result: `30 passed`.
- Backlog update: all Phase C checkbox items now marked complete in `docs/tui_v2_parity_backlog.md`.

## 2026-03-01 TUI v2 parity Phase D slice: profile + settings palette plumbing
- Extended `launch_tui2(...)` to accept optional `profile_service_factory` and `config_service_factory`, in addition to entry service factory.
- Updated CLI preflight wiring (`src/seedpass/cli/__init__.py`) so TUI v2 receives entry/profile/config services from a single initialized manager when available, while preserving existing monkeypatch compatibility in CLI tests.
- Added new TUI v2 palette commands in `src/seedpass/tui_v2/app.py`:
  - `profiles-list`
  - `profile-switch <fingerprint> [password]`
  - `setting-secret <on|off> [delay]`
  - `setting-offline <on|off>`
  - `setting-quick-unlock <on|off>`
- Added toggle parsing helper for robust boolean token handling (`on/off/true/false/...`).
- Added Textual interaction test fakes for profile/config services and new command coverage:
  - `test_tui2_textual_profiles_and_settings_palette_commands`
  - `test_tui2_textual_profiles_and_settings_palette_validation`
- Expanded action-matrix command coverage to include new profile/settings command guard paths.
- Validation run:
  - `.venv/bin/pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py src/tests/test_tui_v2_helpers.py src/tests/test_typer_cli.py`
  - Result: `86 passed`.
- Backlog update (`docs/tui_v2_parity_backlog.md`):
  - marked `secret mode / quick unlock / offline toggles` complete.
  - profile switch/add/remove/list/rename remains open because only list/switch command-path parity is currently implemented; add/remove/rename UX flows still pending.

## 2026-03-01 TUI v2 parity Phase D slice: profile lifecycle + relay/sync command paths
- Extended TUI launch wiring to accept optional `nostr_service_factory` and `sync_service_factory` in `launch_tui2(...)`.
- Updated CLI preflight service bundle (`src/seedpass/cli/__init__.py`) to pass entry/profile/config/nostr/sync services from a shared manager when available, while preserving monkeypatch compatibility in CLI tests.
- Added new palette commands in `src/seedpass/tui_v2/app.py`:
  - profile lifecycle: `profile-add`, `profile-remove <fingerprint>` (plus existing `profiles-list`, `profile-switch`)
  - relays/sync: `relay-list`, `relay-add <url>`, `relay-rm <index>`, `sync-now`, `sync-bg`
- Added Textual interaction fakes + coverage for new service surfaces:
  - fake profile service now supports add/remove
  - new fake nostr service for relay list/add/remove
  - new fake sync service for sync-now/bg paths
- Expanded command matrix coverage to include new profile/relay/sync guard-path commands.
- Validation:
  - `.venv/bin/pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py src/tests/test_tui_v2_helpers.py src/tests/test_typer_cli.py`
  - Result: `86 passed`.
- Backlog status update:
  - Phase D rows for profile and relay/sync remain open because profile rename and relay reset parity are still missing.
  - Added explicit progress note in `docs/tui_v2_parity_backlog.md` documenting currently landed command coverage.

## 2026-03-01 TUI v2 parity Phase D completion slice: profile rename + relay reset
- Service-layer additions in `src/seedpass/core/api.py`:
  - `ProfileService.rename_profile(fingerprint, name)` using fingerprint manager naming support.
  - `NostrService.reset_relays()` to restore default relays, persist config/state, and update active Nostr client relay list.
- TUI palette additions in `src/seedpass/tui_v2/app.py`:
  - `profile-rename <fingerprint> <name>`
  - `relay-reset`
- Existing profile/relay command set now covers:
  - profiles: list/switch/add/remove/rename
  - relays/sync: list/add/remove/reset + sync-now/sync-bg
- Test updates:
  - `src/tests/test_tui_v2_textual_interactions.py` fakes now implement `rename_profile` and `reset_relays`; success/validation tests assert both command paths.
  - `src/tests/test_tui_v2_action_matrix.py` matrix guard coverage includes `profile-rename` and `relay-reset`.
- Validation:
  - `.venv/bin/pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py src/tests/test_tui_v2_helpers.py src/tests/test_typer_cli.py`
  - Result: `86 passed`.
- Backlog update:
  - `docs/tui_v2_parity_backlog.md` now marks both `profile switch/add/remove/list/rename` and `relay view/add/remove/reset + sync controls` complete.
  - Remaining Phase D open items are `inactivity timeout + KDF settings` and checksum/import-export utility actions.

## 2026-03-01 TUI v2 parity Phase D completion slice: inactivity/KDF + checksum/export utilities
- Extended TUI launch dependency injection to include optional `utility_service_factory` and `vault_service_factory`.
- CLI preflight bundle (`src/seedpass/cli/__init__.py`) now provides utility/vault services to TUI v2 when manager-backed services are available.
- Added new settings commands in `src/seedpass/tui_v2/app.py`:
  - `setting-timeout <seconds>`
  - `setting-kdf-iterations <n>`
  - `setting-kdf-mode <mode>`
- Added utility/export commands:
  - `checksum-verify`
  - `checksum-update`
  - `db-export <path>`
  - `db-import <path>`
  - `totp-export <path>`
  - `parent-seed-backup [path] [password]`
- Added support commands to existing profile/relay set:
  - `profile-rename <fingerprint> <name>` and `relay-reset` (wired to new service methods).
- Service-layer additions in `src/seedpass/core/api.py`:
  - `ProfileService.rename_profile(...)`
  - `NostrService.reset_relays()`
- Test coverage updates:
  - `src/tests/test_tui_v2_textual_interactions.py` now has fakes and assertions for all new settings/checksum/export/profile-rename/relay-reset commands.
  - `src/tests/test_tui_v2_action_matrix.py` command matrix includes guard path invocations for the new commands.
- Validation:
  - `.venv/bin/pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py src/tests/test_tui_v2_helpers.py src/tests/test_typer_cli.py`
  - Result: `86 passed`.
- Backlog update:
  - `docs/tui_v2_parity_backlog.md` now marks all Phase D items complete.
  - Remaining backlog focus shifts to Phase E release/CI closure work.

## 2026-03-01 TUI v2 parity Phase E: CI smoke + docs/help closure
- Added dedicated CI smoke script for TUI v2 runtime diagnostics:
  - `scripts/tui2_check_smoke.sh`
  - Executes `seedpass tui2 --check` when CLI binary is available, otherwise falls back to Typer `CliRunner` invocation.
  - Validates JSON output keys (`status`, `backend`, `textual_available`, `message`) and backend value (`textual`).
  - Includes `python`/`python3` fallback handling for portability.
- Wired CI smoke gate into default CI test runner:
  - `scripts/run_ci_tests.sh` now runs `./scripts/tui2_check_smoke.sh` before determinism/full test suite.
- Added explicit workflow smoke step for Poetry matrix:
  - `.github/workflows/tests.yml` includes `poetry run seedpass tui2 --check`.
- Phase E docs/status updates:
  - `docs/tui_v2_parity_backlog.md` marks all Phase E closure items complete and includes release notes.
  - `docs/tui_v2_plan.md` marks the CI smoke command item complete in Phase 0.
  - `docs/tui_v2_parity_checklist.md` adds closure notes for CI smoke and retained legacy fallback paths.
- Validation run:
  - `scripts/tui2_check_smoke.sh` => `tui2 --check smoke: ok`
  - `bash -n scripts/tui2_check_smoke.sh scripts/run_ci_tests.sh` => clean
  - `.venv/bin/pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py src/tests/test_tui_v2_helpers.py src/tests/test_typer_cli.py` => `86 passed`.

## 2026-03-02 TUI v2 UX fixes: stale selection panel, clipped nav/help, and sensitive feedback clarity
- Reproduced screenshot-reported UX issues in TUI v2:
  - Left panel could show stale `Selected: (none)` even while entry details were loaded.
  - Left panel command text could clip/wrap aggressively and hide actionable hints.
  - Sensitive reveal/QR confirmation paths could appear like no-op when only status line changed.
  - QR output could become visually distorted by line wrapping in the secret panel.
- Fixes implemented in `src/seedpass/tui_v2/app.py`:
  - `_show_entry(...)` now refreshes the filters panel immediately so selected state is always in sync.
  - Added `on_list_view_highlighted(...)` to keep selected entry aligned with list highlight navigation.
  - Left filters pane now uses `height: 1fr` + `overflow: auto` to prevent clipping.
  - Secret panel now sets `text-wrap: nowrap` to preserve QR matrix geometry.
  - Footer top border removed to avoid visual crowding at the bottom status/footer region.
  - Filters/nav action copy trimmed to avoid forced line wraps in narrow terminals.
  - Confirmation-required reveal/QR actions now also write explicit instructions into `#secret-detail`.
- Added regression coverage in `src/tests/test_tui_v2_textual_interactions.py`:
  - `test_tui2_textual_filters_panel_tracks_selected_entry` ensures left-panel selected summary updates after opening a different entry.
- Validation:
  - `pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py src/tests/test_tui_v2_helpers.py` -> `33 passed`.
  - `python scripts/ai_tui2_agent_test.py --scenario core --verbose` -> `[PASS] core`.

## 2026-03-02 Hardening checklist execution (post TUI v2 UX patch)
- Completed requested hardening items in repo workspace:
  1) CI-equivalent run via `scripts/run_ci_tests.sh`: PASS.
     - Determinism gate: `43 passed, 950 skipped`.
     - Full suite: `977 passed, 16 skipped`.
  2) Installer smoke (`beta`) via `scripts/installer_smoke_unix.sh`:
     - `mode=tui`: PASS.
     - `mode=both`: PASS (GUI intentionally skipped in headless runtime).
  3) Parity bug-bash harnesses:
     - `scripts/ai_tui2_agent_test.py --scenario extended --verbose`: PASS.
     - `scripts/ai_tui_agent_test.py --scenario extended --verbose`: PASS.
- Added release note document: `docs/beta_hardening_2026-03-02.md` with checklist commands, results, and residual operational warning about stale launcher binaries on PATH.
- Practical note: Installer repeatedly warns about stale `/home/user/.local/bin/seedpass` entries; this does not fail install but can obscure which binary users are executing.

## 2026-03-02 Next parity slice: keyboard-path managed-account sensitive actions
- Added explicit keyboard-path TUI v2 regression coverage for managed-account sensitive actions.
- New test in `src/tests/test_tui_v2_textual_interactions.py`:
  - `test_tui2_textual_managed_account_keyboard_reveal_and_qr`
  - Validates pressing `v` triggers confirmation-required reveal messaging for managed-account entries.
  - Validates pressing `g` renders managed-account QR payload after list focus is set.
- Note on test ergonomics:
  - Search input can capture keystrokes by default; test now focuses `#entry-list` before keybinding presses to exercise app-level binding path reliably.
- Validation run:
  - `pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py src/tests/test_tui_v2_helpers.py` -> `34 passed`.

## 2026-03-02 Centralized dev planning doc added
- Added `docs/dev_control_center.md` as the single decision-layer document for what to work on next.
- The control center now links plan, parity, security, QA, and hardening documents and includes a prioritized next-step queue.
- Added `docs/README.md` “Start Here” link pointing to `dev_control_center.md`.
- Pre-slice health verification executed first:
  - remote sync check on `origin/beta` (no new remote commits)
  - `scripts/run_ci_tests.sh` pass with full suite: `979 passed, 16 skipped`, coverage `85.65%`.

## 2026-03-02 Slice A implementation progress: managed-account session parity
- Added parity matrix doc: `docs/tui_v2_legacy_parity_matrix.md` and linked it from control-center/readme docs.
- Implemented managed-account session controls in TUI v2 palette:
  - `managed-load (optional: entry_id)`
  - `managed-exit`
- Added core service wrappers in `src/seedpass/core/api.py`:
  - `EntryService.load_managed_account(entry_id)`
  - `EntryService.exit_managed_account()`
- Added tests:
  - `src/tests/test_tui_v2_textual_interactions.py` (session command behavior + validation)
  - `src/tests/test_tui_v2_action_matrix.py` (command matrix coverage)
  - `src/tests/test_core_api_services.py` (service wrapper calls)
- Validation:
  - `pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py src/tests/test_core_api_services.py`
  - Result: `86 passed`.
- Updated matrix priorities: next parity target is explicit Nostr maintenance commands (`reset sync state`, `fresh namespace`).

## 2026-03-02 Next gap landed: Nostr maintenance parity in TUI v2
- Implemented two legacy Nostr maintenance equivalents in TUI v2 palette:
  - `nostr-reset-sync-state`
  - `nostr-fresh-namespace`
- Added service-layer methods in `src/seedpass/core/api.py` (`NostrService`):
  - `reset_sync_state()`
  - `start_fresh_namespace()`
  - includes runtime sync-state clearing and account index management.
- Added/updated tests:
  - `src/tests/test_tui_v2_textual_interactions.py` (happy path + unavailable/usage validation)
  - `src/tests/test_tui_v2_action_matrix.py` (command matrix coverage)
  - `src/tests/test_core_api_services.py` (service method behavior)
- Validation:
  - `pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py src/tests/test_core_api_services.py`
  - Result: `88 passed`.
- Updated planning docs:
  - `docs/tui_v2_legacy_parity_matrix.md` marks Nostr maintenance parity as implemented.
  - `docs/dev_control_center.md` now points to archived-only view/filter as the next parity target.

## 2026-03-02 Next parity slice landed: archived view/filter parity in TUI v2
- Added archive-scope support across TUI v2 entry browsing with three modes:
  - `active` (default, excludes archived entries)
  - `all` (includes active + archived)
  - `archived` (archived-only)
- TUI v2 updates in `src/seedpass/tui_v2/app.py`:
  - new keybinding: `h` (`action_cycle_archive_scope`)
  - new palette command: `archive-filter <active|all|archived>`
  - left filter panel now shows `Archive: <scope>`
  - search loads now pass archive scope to service search.
- Core wrapper updates in `src/seedpass/core/api.py`:
  - `EntryService.search_entries(...)` now accepts
    - `include_archived: bool = False`
    - `archived_only: bool = False`
  - wrapper filters archived rows deterministically on top of entry-manager search results.
- UX parity fix bundled:
  - palette `archive`/`restore` branch now returns correctly after success.
  - archive/restore flows preserve selected-entry context when an archived item leaves the active view, enabling immediate restore roundtrip without forced reselection.
- Test coverage updates:
  - `src/tests/test_core_api_services.py`: archive include/exclude/only behavior for `EntryService.search_entries`.
  - `src/tests/test_tui_v2_textual_interactions.py`: new archive-scope interaction test.
  - updated TUI fake services across
    - `test_tui_v2_textual_interactions.py`
    - `test_tui_v2_action_matrix.py`
    - `test_tui_v2_kb_scale_stress.py`
    - `test_tui_v2_parity_scenarios.py`
    to accept archive-scope args.
- Validation run:
  - `pytest -q src/tests/test_core_api_services.py src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py src/tests/test_tui_v2_kb_scale_stress.py src/tests/test_tui_v2_parity_scenarios.py`
  - Result: `96 passed, 1 skipped`.
- Planning docs updated:
  - `docs/tui_v2_legacy_parity_matrix.md` marks archived-only view parity implemented.
  - `docs/dev_control_center.md` next target updated to dedicated `npub` utility command parity.

## 2026-03-02 Next parity slice landed: dedicated Nostr npub utility command
- Implemented utility-style Nostr pubkey command in TUI v2 palette:
  - `npub`
  - alias: `nostr-pubkey`
- Behavior in `src/seedpass/tui_v2/app.py`:
  - validates no-arg usage (`Usage: npub`)
  - requires Nostr service availability and `get_pubkey()` support
  - fetches active profile pubkey and renders it in `#secret-detail`
  - includes QR payload rendering for `nostr:<npub>` when QR runtime is available
  - status line reports `Displayed active Nostr pubkey`
- Help/discovery text updated to include `npub` in palette placeholder/help/actions copy.
- Test coverage updates:
  - `src/tests/test_tui_v2_textual_interactions.py`
    - success path in profiles/settings command flow (`npub` status + panel assertion)
    - unavailable service path (`Nostr service unavailable`)
    - invalid usage path (`npub now` -> `Usage: npub`)
  - `src/tests/test_tui_v2_action_matrix.py`
    - matrix command-path coverage invokes `npub`.
- Parity docs update:
  - `docs/tui_v2_legacy_parity_matrix.md` now marks `Display npub` as Implemented.
  - `docs/dev_control_center.md` progress notes now include `npub` parity completion and shift next target to checklist closure.

## 2026-03-02 Parity checklist closure: full legacy workflow coverage
- Executed parity bug-bash harnesses for both interactive stacks:
  - `python scripts/ai_tui2_agent_test.py --scenario extended --verbose`
    - Result: `PASS`
    - Report: `artifacts/agent_tui2_test/20260302T135526Z/report.json`
  - `python scripts/ai_tui_agent_test.py --scenario extended --verbose`
    - Result: `PASS`
    - Report: `artifacts/agent_tui_test/20260302T135526Z/report.json`
- Updated parity documentation:
  - `docs/tui_v2_parity_checklist.md`
    - status changed to parity-complete on `beta`
    - `Full legacy workflow coverage` changed from `Pending` to `Yes`
    - added evidence section with exact commands and report paths.
  - `docs/dev_control_center.md`
    - removed parity-closure pending state
    - shifted priority stack to post-parity cutover readiness (testing gates, Nostr resilience, cutover memo, supply-chain readiness).

## 2026-03-02 Testing-gate hardening: TUI v2 + service coverage thresholds
- Added dedicated focused gate script: `scripts/tui2_coverage_gate.sh`.
- Gate behavior:
  - uses `.venv/bin/python` when available (fallback `python`/`python3`)
  - checks Textual runtime availability before running focused TUI v2 coverage suite
  - runs focused tests with coverage output: `artifacts/coverage/coverage.tui2_gate.json`
  - enforces thresholds via `scripts/check_critical_coverage.py --no-default-thresholds`:
    - `src/seedpass/tui_v2/app.py >= 78%`
    - `src/seedpass/core/api.py >= 85%`
  - writes machine-readable result to `artifacts/coverage/critical_gate.tui2.json`.
- Strengthened default critical-coverage policy:
  - `scripts/check_critical_coverage.py` default thresholds now include:
    - `src/seedpass/core/api.py = 85%`.
- CI runner hardening:
  - `scripts/run_ci_tests.sh` now enables `CRITICAL_COVERAGE_GATE` by default (`1`).
  - adds JSON output for full-suite gate: `artifacts/coverage/critical_gate.full.json`.
  - adds focused TUI v2 gate call controlled by `TUI2_COVERAGE_GATE` (default `1`).
  - coverage-gate Python invocation now uses `python`/`python3` fallback resolution.
- Test/doc updates:
  - `src/tests/test_check_critical_coverage.py` includes assertion for new default API threshold.
  - docs updated in:
    - `docs/ai_agent_tui_testing.md`
    - `docs/security_readiness_checklist.md`
    - `docs/dev_control_center.md`
- Validation run (this slice):
  - `pytest -q src/tests/test_check_critical_coverage.py` -> `9 passed`
  - `./scripts/tui2_coverage_gate.sh` -> PASS
    - `src/seedpass/core/api.py: 86.64%`
    - `src/seedpass/tui_v2/app.py: 79.87%`
  - `python3 scripts/check_critical_coverage.py artifacts/coverage/coverage.json --json-output artifacts/coverage/critical_gate.full.json` -> PASS.

## 2026-03-02 Nostr resilience deterministic failure-mode suite expansion
- Added new deterministic resilience tests in `src/tests/test_nostr_resilience_failure_modes.py` targeting `PasswordManager` Nostr sync error paths.
- New covered scenarios:
  - `sync_vault_async` returns `None` and sets explicit error when encrypted index bytes are unavailable.
  - `sync_vault_async` preserves relay/publish error text when `publish_snapshot` fails to produce an event ID.
  - `sync_vault_async` sets fallback publish failure error when no relay error text is provided.
  - `sync_index_from_nostr_async` emits warning notification when snapshot fetch returns no result and client has `last_error`.
  - `sync_index_from_nostr_async` emits warning notification on snapshot-fetch exceptions.
- Validation run:
  - `pytest -q src/tests/test_nostr_resilience_failure_modes.py src/tests/test_background_vault_sync_paths.py src/tests/test_post_sync_messages.py src/tests/test_offline_mode_behavior.py`
  - Result: `16 passed`.
- Docs updated:
  - `docs/security_readiness_checklist.md` now includes `test_nostr_resilience_failure_modes.py` under Nostr resilience evidence.
  - `docs/dev_control_center.md` progress notes updated to reflect deterministic Nostr resilience suite expansion.

## 2026-03-02 Cutover memo refresh and doc alignment
- Updated `docs/tui_v2_cutover_decision.md` to reflect current `beta` reality:
  - default route is TUI v2 with explicit legacy fallback paths retained
  - parity closure and bug-bash evidence status
  - strengthened CI/testing gates (runtime smoke + critical coverage + focused TUI2 coverage)
  - remaining blockers reframed to release hardening areas (soak validation, supply-chain completion, operational runbooks).
- Aligned planning docs:
  - `docs/dev_control_center.md` next-step priorities updated to remove completed memo-refresh item and track current hardening priorities.
  - `docs/tui_v2_plan.md` status updated from draft wording to implemented/reference-plan wording.
