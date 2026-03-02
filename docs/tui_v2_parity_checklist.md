# TUI v2 Parity Checklist

Status: Parity-complete on `beta` (updated 2026-03-02).

This checklist tracks readiness to switch default interactive mode from legacy TUI to `seedpass tui2`.

## Scope

- Legacy baseline: current default `seedpass` interactive path.
- Candidate: `seedpass tui2` (Textual).
- Non-goal for cutover: replacing CLI/API behavior.

## Current Parity

| Area | Legacy TUI | TUI v2 | Notes |
|---|---|---|---|
| Entry list/search | Yes | Yes | Includes kind filter and search. |
| Entry detail view | Yes | Yes | Large document content preview is truncated for performance. |
| Archive/restore | Yes | Yes | Keyboard and command palette paths. |
| Document editing | Partial | Yes | Save/cancel flow in editor panel. |
| Graph links list | Limited | Yes | Dedicated links panel. |
| Link add/remove | Limited | Yes | Via command palette commands. |
| Neighbor traversal | No | Yes | Link cursor + open target entry. |
| Command discoverability | Menu-driven | Partial | Keybind hints and palette `help`. |
| Full legacy workflow coverage | Yes | Yes | Closed with parity matrix completion + bug-bash evidence (2026-03-02). |

## Phase 4 Deliverables

- [x] Feature parity checklist document.
- [x] First UX/perf pass for large vaults.
  - paginated entry list rendering (`p`/`n`, `page-*` palette commands)
  - document content preview truncation in detail panel
- [x] Error messaging and recovery flow review.
  - unified failure status messaging
  - retry shortcut (`x`) and palette `retry` command
- [x] Cutover decision memo (`seedpass` default switch timing).

## Risks Remaining

- Incomplete parity for legacy-only interactive operations not yet mapped into TUI v2.
- Textual runtime/version behavior can vary by environment.
- Large-vault validation is bounded to deterministic pagination/preview checks and should be expanded with full end-to-end sync workloads.

## Validation Checklist Before Cutover

- [x] Define and run deterministic parity scenarios across entry kinds.
  - `src/tests/test_tui_v2_parity_scenarios.py`
- [x] Add Textual interaction tests for list/search/edit/link/pagination flows.
  - `src/tests/test_tui_v2_textual_interactions.py` (skips when `textual` is unavailable).
- [x] Add non-UI unit tests for TUI v2 helper logic.
  - `src/tests/test_tui_v2_helpers.py` covers command parsing, pagination, and detail truncation.
- [x] Verify large vault behavior with realistic data volume in CI-like environment.
  - `src/tests/test_tui_v2_large_vault_validation.py`
  - standard: `10,000` rows, stress: `50,000` rows (`--stress`)
- [x] Confirm help text and docs match shipped keybindings and palette commands.
  - Updated `seedpass tui2 --help`, capabilities hints, and docs discoverability commands.

## Ongoing Tracking

- Active parity continuation and checkoff queue:
  - `docs/tui_v2_parity_backlog.md`

## Parity Closure Evidence (2026-03-02)

- Legacy interactive bug-bash harness:
  - `python scripts/ai_tui_agent_test.py --scenario extended --verbose`
  - Result: `PASS`
  - Report: `artifacts/agent_tui_test/20260302T135526Z/report.json`
- Textual TUI v2 bug-bash harness:
  - `python scripts/ai_tui2_agent_test.py --scenario extended --verbose`
  - Result: `PASS`
  - Report: `artifacts/agent_tui2_test/20260302T135526Z/report.json`
- Parity matrix status:
  - `docs/tui_v2_legacy_parity_matrix.md` now marks mapped legacy actions as implemented.

## Phase E Closure Notes

- CI smoke now explicitly validates `seedpass tui2 --check` output shape:
  - `scripts/tui2_check_smoke.sh` (called from `scripts/run_ci_tests.sh`)
  - `.github/workflows/tests.yml` (`poetry run seedpass tui2 --check`)
- Legacy fallback paths remain intentionally available during hardening:
  - `seedpass --legacy-tui`
  - `seedpass legacy`
  - `seedpass tui2 --fallback-legacy`
