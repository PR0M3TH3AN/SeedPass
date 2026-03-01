# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased] - 2026-02-16

### Added

## [Unreleased] - 2026-02-28

### Added
- Added favicon and switched accent palette to green for landing page.
- Added comprehensive unit tests for `generate_fingerprint`.
- Added unit test for `StatsManager.reset` method.
- Added test to verify `atomic_write` cleanup on failure.
- Added test to verify `verify_checksum` behavior when file is missing.

### Changed
- Refactored `modify_entry` to reduce complexity by using helper methods.
- Refactored entry menus to use generic `MenuHandler.run_menu`.
- Refactored GUI backend config to `constants.py`.
- Refactored `handle_add_*` methods to remove duplication.
- Refactored `Vault.load_index` into smaller private methods.
- Refactored `_enforce_complexity` in `password_generation.py`.
- Refactored `display_sensitive_entry_info` into `DisplayService`.
- Refactored `initialize_managers` in `PasswordManager` for better readability.
- Refactored imghdr compatibility hack to a dedicated compat module.

### Fixed
- Fixed `test_ai_tui_agent_harness` on Windows platform skip handling.
- Removed unformatted `patch.py` from git history and repo.
- Fixed race condition in backup file permissions.
- Added pycryptodome dependency for PGP RSA features.
- Prevented arbitrary file overwrite in `backup_parent_seed`.
- Fixed legacy empty salt key derivation issues.
- Fixed index verification for TOTP in modify entry test.
- Fixed macOS build script and updated `requirements.lock`.

### Performance
- Offloaded blocking `import_vault` operations to thread.
