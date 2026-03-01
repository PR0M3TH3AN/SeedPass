# TUI v2 Parity Checklist

Status: In progress on `beta` (updated 2026-03-01).

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
| Full legacy workflow coverage | Yes | Pending | Additional edge-case parity still needed. |

## Phase 4 Deliverables

- [x] Feature parity checklist document.
- [x] First UX/perf pass for large vaults.
  - paginated entry list rendering (`p`/`n`, `page-*` palette commands)
  - document content preview truncation in detail panel
- [ ] Error messaging and recovery flow review.
- [ ] Cutover decision memo (`seedpass` default switch timing).

## Risks Remaining

- Incomplete parity for legacy-only interactive operations not yet mapped into TUI v2.
- Textual runtime/version behavior can vary by environment.
- No dedicated Textual interaction test suite yet for pagination and graph traversal.

## Validation Checklist Before Cutover

- [ ] Define and run deterministic parity scenarios across entry kinds.
- [ ] Add Textual interaction tests for list/search/edit/link/pagination flows.
- [ ] Verify large vault behavior with realistic data volume in CI-like environment.
- [ ] Confirm help text and docs match shipped keybindings and palette commands.
