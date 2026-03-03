# Memory Update — SeedPass TUI v3 Development — 2026-03-03

## Key findings
- Nostr Relay Management is now implemented in TUI v3 (`src/seedpass/tui_v3/screens/relays.py`) via the `relay-list` palette command.
- Textual UI updates from asynchronous workers requires executing from the main thread using `self.app.call_from_thread()`, otherwise you will encounter unexpected thread safety warnings crashing the app. This was correctly used for `sync_service.sync()` background operations.
- The `pytest` execution of parity tests natively sources from the local environment. Ensure testing inside the virtual environment properly maps module paths (e.g., using `PYTHONPATH=. pytest ...` from the `src` directory) when `src-layout` paths conflict with old `site-packages` installs, which causes confusing `AttributeError` tracebacks on customized files.
- The `SettingsScreen` and TUI v3 components now rely on the standard Textual `app.notify()` for the "Unified snackbar/toast system" — giving uniform, built-in styling for service feedback.

## Patterns / reusable knowledge
- Direct configuration modification of arrays (like `relays`) should favor using dedicated service adapters over direct `ConfigService` modifications if they aren't fully wrapped for list operations. Using `app.services["nostr"]` for relay additions/removals is the preferred pattern.
