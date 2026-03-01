# TUI v2 Plan (Textual)

Status: Draft implementation plan on `beta` branch.

Goal: Introduce a modern, modular TUI (`seedpass tui2`) without rewriting core logic or breaking existing CLI/API behavior.

## Constraints

- Keep `seedpass.core` as the source of truth for all business logic.
- Keep current TUI (`seedpass` default path) operational during migration.
- Maintain interface modularity:
  - CLI/TUI
  - API
  - future GUI

## Proposed Stack

- Primary: `Textual` for TUI v2 shell and interaction model.
- Keep dependency optional initially; runtime check from `seedpass tui2 --check`.

## Architecture

1. `seedpass.core`
- Existing logic/services (`EntryManager`, `EntryService`, sync, vault, policy).

2. `seedpass.app` (future thin orchestration layer)
- UI-agnostic use-cases and view-model mappers.
- Shared by Textual TUI and future GUI.

3. Interface adapters
- `seedpass.cli` (Typer commands)
- `seedpass.tui_v2` (Textual app)
- `seedpass.api` (FastAPI)

## Phased Rollout

### Phase 0: Scaffold (this PR)
- [x] Add plan doc.
- [x] Add `seedpass tui2` command.
- [x] Add runtime check utility and placeholder launcher.
- [ ] Add CI smoke command for `seedpass tui2 --check`.

### Phase 1: Read-only shell
- [x] Textual app skeleton with 3-pane layout:
  - filters panel
  - entry list panel
  - details panel
- [ ] Unlock/profile context hookup.
- [x] Entry list/search/detail read paths.
- [x] Status line for sync/profile/lock state.

### Phase 2: Core editing workflows
- [x] Archive/restore action + document modify flow.
- [x] Document editor panel with dirty-state and save/cancel.
- [x] Keybindings + command palette.

### Phase 3: Graph workflows
- [x] Entry links panel (list, add, remove).
- [x] Relation-aware link filter controls.
- [x] Neighbor navigation and quick traversal.

### Phase 4: Cutover readiness
- [x] Feature parity checklist against legacy TUI.
- [x] UX/perf pass for large vaults.
- [x] Error messaging and recovery flows.
- [x] Decide default switch timing (`seedpass` -> `tui2`).

## Test Strategy

- Unit tests:
  - runtime checks and command wiring.
  - view-model transformations (when `seedpass.app` exists).
- Integration tests:
  - command-level smoke (`seedpass tui2 --check`).
  - later: Textual interaction tests for list/search/edit/link.
- Regression:
  - full suite must remain green during phased migration.

## Risks and Mitigations

- Risk: UI code bypasses core invariants.
  - Mitigation: enforce service-layer-only mutation from TUI.
- Risk: dependency churn (`textual` changes).
  - Mitigation: pin versions when enabling default path.
- Risk: branch drift while both TUIs exist.
  - Mitigation: parity checklist and shared orchestration layer.

## Deliverables

- New command:
  - `seedpass tui2`
  - `seedpass tui2 --check`
- New package:
  - `seedpass/tui_v2/`
- Docs updates:
  - this file listed in docs index and discoverability nav.
