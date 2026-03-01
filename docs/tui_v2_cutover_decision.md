# TUI v2 Cutover Decision Memo

Date: March 1, 2026
Branch: `beta`
Decision owner: SeedPass maintainers

## Decision

Do not switch the default interactive entrypoint (`seedpass`) to TUI v2 yet.

Recommended rollout:
- Keep legacy TUI as default for the next release.
- Keep `seedpass tui2` as the opt-in path.
- Schedule default switch only after cutover gates below are met.

## Rationale

TUI v2 now covers the core workflows (search/filter/detail, document editing, graph links, relation traversal, pagination, retryable failures), but the project still has explicit remaining risks:
- full legacy workflow parity is still marked pending
- no dedicated Textual interaction test suite yet
- cross-environment runtime behavior for Textual still needs broader validation

Switching defaults before those gates are closed adds avoidable regression risk.

## Cutover Gates (Required)

1. Parity closure
- Complete and verify remaining legacy-only interactive flows.
- Update parity checklist so no high-severity gap remains.

2. Test coverage
- Add automated Textual interaction tests for:
  - list/search/filter + pagination
  - document edit save/cancel
  - link add/remove/filter/open traversal
  - retry-on-error paths

3. Large-vault validation
- Run deterministic stress scenarios with realistic vault sizes.
- Confirm acceptable responsiveness and no functional regressions.

4. Docs/help alignment
- Ensure `--help`, keybinding hints, and docs match shipped behavior.

5. Release safety
- Keep a one-release fallback flag/path to legacy TUI.
- Confirm rollback steps in release notes.

## Proposed Timing

- Target decision checkpoint: next `beta` hardening cycle after test and parity gates are complete.
- Earliest practical default switch: first release after all gates pass in CI and manual smoke checks.

## Rollout Plan

1. Release N
- Default: legacy TUI.
- Promote `seedpass tui2` in docs and help text.
- Collect bug reports and telemetry signals (where available).

2. Release N+1 (conditional)
- Default: TUI v2.
- Keep explicit legacy fallback command/flag for one release.

3. Release N+2
- Re-evaluate legacy fallback retention based on stability.

## Rollback Plan

If a cutover regression is detected:
- Immediately revert default routing to legacy TUI.
- Keep TUI v2 available as opt-in for continued fixes.
- Publish a short incident note with repro case and mitigation timeline.

## Implementation Note

When cutover is approved, update CLI callback routing in
`src/seedpass/cli/__init__.py` so `seedpass` invokes TUI v2 by default while preserving an explicit legacy path.
