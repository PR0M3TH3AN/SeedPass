# Memory Update — SeedPass TUI v3 Development — 2026-03-03

## Key findings
- Nostr Relay Management is now implemented in TUI v3 (`src/seedpass/tui_v3/screens/relays.py`) via the `relay-list` palette command.
- Textual UI updates from asynchronous workers requires executing from the main thread using `self.app.call_from_thread()`, otherwise you will encounter unexpected thread safety warnings crashing the app. This was correctly used for `sync_service.sync()` background operations.
- The `pytest` execution of parity tests natively sources from the local environment. Ensure testing inside the virtual environment properly maps module paths (e.g., using `PYTHONPATH=. pytest ...` from the `src` directory) when `src-layout` paths conflict with old `site-packages` installs, which causes confusing `AttributeError` tracebacks on customized files.
- The `SettingsScreen` and TUI v3 components now rely on the standard Textual `app.notify()` for the "Unified snackbar/toast system" — giving uniform, built-in styling for service feedback.

## Patterns / reusable knowledge
- Direct configuration modification of arrays (like `relays`) should favor using dedicated service adapters over direct `ConfigService` modifications if they aren't fully wrapped for list operations. Using `app.services["nostr"]` for relay additions/removals is the preferred pattern.
- The cohesive retro palette across the TUI v3 mockups hinges on high-contrast `#999999` backgrounds, `#000000` text/borders, and crisp `#ffffff` inputs. All standalone screens (`SettingsScreen`, `MaximizedInspectorScreen`, `AddEntryScreen`, etc.) must strictly conform to these CSS constants rather than the legacy v2 neon green (`#58f29d`, `#080a0c`).
- In automated Textual UI interactive parity testing (`interactive_agent_tui_test.py`), avoid explicitly sending `await pilot.press('ctrl+p')` if standard textual palettes shadow custom `CommandPalette` widgets. Directly calling `app.action_open_palette()` guarantees stable integration assertions.
- When mirroring nested manager logic (like BIP-85 sub-account loads), UI "breadcrumbs" should derive their explicit path strings from parsing the manager's `profile_stack` via a decoupled reactive property (e.g. `active_breadcrumb`), rather than mutating the core `active_fingerprint` references used for caching and view filtering.

## Session addendum — os-eco setup (2026-03-03)
- `ov init -y` successfully bootstraps `.overstory/`, `.mulch/`, `.seeds/`, `.canopy/`, and also auto-appends onboarding blocks to `CLAUDE.md` and merge rules to `.gitattributes`.
- For this Python repo, `.overstory/config.yaml` should be adjusted from Bun defaults to `canonicalBranch: beta` and Python quality gates (`pytest`, `scripts/run_ci_tests.sh`) to avoid incorrect guardrails.
- Overstory/Codex model handling in this repo required follow-up validation; see the later "Overstory/Codex spawn fix" section for the corrected working configuration.

## Session addendum — Overstory/Codex spawn fix (2026-03-03)
- Reproduced `ov sling` failure: `Failed to send keys to tmux session ... can't find pane` after a clean launch path.
- Root cause was invalid Codex model aliases in `.overstory/agent-manifest.json` (`haiku/sonnet/opus`) causing `codex exec` to exit immediately; `codex exec --model sonnet` fails with unsupported-model error on ChatGPT-backed Codex accounts.
- Working configuration on this machine:
  - Keep `.overstory/config.yaml` `models:` empty (Overstory v0.7.9 rejects bare `gpt-*` entries in this block unless provider-prefixed, which Codex account mode does not accept).
  - Set each agent `model` in `.overstory/agent-manifest.json` to `gpt-5.3-codex`.
- Secondary requirement: tmux server must be running before sling (`tmux new-session -d -s ov-bootstrap 'bash'` is enough); otherwise Overstory errors with `Tmux server is not running`.
- Added a dedicated personal swarm runbook at repo root: `OVERSTORY_SWARM_TUTORIAL.md` with verified commands, failure modes, and recovery flow for this SeedPass setup.

## Session addendum — TORCH -> Mulch migration + repo health scan (2026-03-03)
- Migrated high-signal operational/project learnings into Mulch domain `seedpass` (`.mulch/expertise/seedpass.jsonl`) including Overstory/Codex model pitfalls, tmux bootstrap convention, TUI v3 threading/notification patterns, and runbook reference.
- Full CI-equivalent run currently reports `1057 passed, 16 skipped, 7 failed`; failures are concentrated in `src/tests/test_tui_v2_textual_interactions.py` and are mostly copy/text assertions or profile-tree expectation drift.
- Determinism regression caused by tuple arity mismatch was fixed by updating `src/tests/test_deterministic_artifact_regression.py` to unpack `derive_pgp_key` as `(priv, pub, fp)` and correcting `derive_pgp_key` type/docs in `src/seedpass/core/password_generation.py`.
- Local quality signal gaps: `black --check .` currently reports 20 files needing formatting, and `ruff`/`mypy` are configured in project metadata or pre-commit but not installed/gated in the current local environment by default.

## Session addendum — v2/v3 gate and hardening updates (2026-03-03)
- Repaired 7 failing TUI v2 interaction regressions in `src/seedpass/tui_v2/app.py`:
  - action-strip click coordinate handling (zero-based)
  - settings shortcut restored to palette prefix behavior (`setting-`)
  - managed-load validation message compatibility
  - profile-switch now auto-expands active profile-tree branch
  - sensitive confirmation status text normalized to include "requires confirmation"
- Added TUI v3 focused coverage gate script: `scripts/tui3_coverage_gate.sh` and wired it into `scripts/run_ci_tests.sh` behind `TUI3_COVERAGE_GATE` (default on).
- Hardened TUI v3 sensitive payload resolution (`src/seedpass/tui_v3/app.py`) for legacy service compatibility:
  - PGP payloads may be 2-tuple or 3-tuple.
  - Seed getters may accept `(entry_id)` or `(entry_id, parent_seed)`.
- Added regression tests in `src/tests/test_tui_v3_parity.py` to lock this compatibility behavior.
- Current CI-equivalent state:
  - Full main suite passes (`1064 passed, 16 skipped`), but existing `tui2_coverage_gate.sh` still fails `src/seedpass/core/api.py >= 85` on its focused subset (`68.79%`) and needs separate gate policy/workload adjustment.

## Session addendum — v3 grid focus + graph navigation baseline (2026-03-06)
- Root cause for the reported v3 "main index list / scrolling" bug was focus management, not `DataTable` scrolling itself:
  - first render focus landed on the hidden command palette input
  - arrow-key navigation did nothing until the entry table was manually focused
- Stable fix:
  - `MainScreen.on_mount()` now focuses `#entry-data-table`
  - closing the command palette restores focus to `#entry-data-table` instead of clearing focus
- Reusable v3 search/navigation pattern:
  - persist the active search query in app state so refresh/filter/sort changes do not silently clear the current result set
  - keep sort and mode changes as explicit app actions (`action_set_search_mode`, `action_set_search_sort`) so toolbar buttons and palette commands stay aligned
- Search/graph baseline shipped:
  - `SearchService.linked_neighbors(...)` now returns deterministic incoming/outgoing link cards
  - `SearchService.relation_summary(...)` now returns grouped relation counts
  - TUI v3 inspector now exposes a linked-items panel with direct open-entry actions
  - TUI v3 grid now has explicit filter/mode/sort buttons instead of palette-only control
