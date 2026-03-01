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
