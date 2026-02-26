# Memory Update — codex — 2026-02-26

## Key findings
- Full test suite now passes: `766 passed, 11 skipped`.
- `DisplayService` had diverged from `seedpass.core.manager` interactive helpers, causing test monkeypatches to miss and resulting in flaky behavior.

## Bugs fixed
- Fixed TOTP retrieve/edit regression where `test_edit_totp_period_from_retrieve` could fail in-suite because TOTP screen consumed input via unpatched `display_service.timed_input`.
- Fixed suite hang at `test_show_seed_entry_details` caused by `display_service.confirm_action` bypassing patched `manager.confirm_action`, leading to infinite prompt loop on empty input.

## Patterns / reusable knowledge
- In this codebase, interactive helpers should be called through `seedpass.core.manager` symbols (`confirm_action`, `timed_input`, `copy_to_clipboard`) to keep behavior and tests consistent.

## Follow-up (warnings cleanup)
- Added pytest `markers` registration for `network` under `[tool.pytest.ini_options]` to remove `PytestUnknownMarkWarning`.
- Added narrow pytest warning filters for known third-party GUI deprecation noise (`Pack.padding*`).
- For `imghdr` deprecation triggered during `test_imghdr_stub` import, added a local `warnings.filterwarnings(...)` at top of that test module to suppress import-time warning deterministically.
- Verified final suite status: `766 passed, 11 skipped`, no warnings.
