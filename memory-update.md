# Memory Update (2026-02-25)

## Docs Cleanup
- Replaced `docs/README.md` content that referenced Archivox with a SeedPass-focused docs index.
- Updated docs-site default title in `docs/src/config/loadConfig.js` from `Archivox` to `SeedPass Docs`.

## Outcome
- Removed stale Archivox branding from the docs README and default docs title so the correct SeedPass README/content is displayed.

## Supply Chain and Release Integrity (Checklist #8)
- Added a dedicated release integrity workflow at `.github/workflows/release-integrity.yml`.
- Workflow now enforces lockfile drift checks, runs `pip-audit`, builds release artifacts, generates `SHA256SUMS`, signs checksum manifest with keyless `cosign`, and publishes signatures/certs with release assets.
- Added `scripts/release_integrity.py` CLI with `check-lockfile`, `generate`, and `verify` subcommands.
- Added reusable checksum logic in `src/seedpass/release_integrity.py` and regression tests in `src/tests/test_release_integrity_utils.py`.
- Updated `docs/security_readiness_checklist.md` item #8 from `Not Started` to `In Progress` with evidence links.
- Added process documentation in `docs/supply_chain_release_integrity.md` and linked it from `docs/README.md` and `README.md`.

## Determinism Regression Guardrail
- Added `src/tests/test_deterministic_artifact_regression.py` to lock deterministic vectors at index `352` for password, SSH, seed phrase, TOTP, PGP (fingerprint + armored hash), and Nostr keys.
- Added repeatability assertions for same-seed/same-index derivation in the same run.
- Logged explicit remaining tasks to finish checklist item #8 in both `docs/supply_chain_release_integrity.md` and `TODO.md`.

## CI Determinism Enforcement
- Expanded deterministic regression vectors to cover indices `0`, `1`, `352`, and `1024` across password, SSH, seed phrase, TOTP, and Nostr outputs.
- Added pinned PGP vectors for both `ed25519` and `rsa` at index `352` (fingerprints + armored key hashes).
- Added explicit deterministic regression steps to push CI workflows:
  - `.github/workflows/python-ci.yml`
  - `.github/workflows/tests.yml`

## Profile Unlock Failure Recovery
- Hardened startup profile selection to avoid fatal crash loops when unlock/decryption fails or is cancelled.
- `select_fingerprint(...)` now returns `False` on unlock/setup failure instead of always raising; selection menu now keeps the user in-flow.
- Added profile recovery flow `recover_profile_with_blank_index()` reachable from seed-profile selection menu.
- Recovery flow verifies that user-provided seed matches selected fingerprint, then re-encrypts seed and resets local entry index/checksum files to a blank state.
- Fixed "switch to existing profile" path during add-new-seed so it does not call `initialize_managers()` without an initialized `EncryptionManager`.
- Added regression tests in `src/tests/test_profile_recovery_flow.py` for these paths.

## TUI Crash Hardening
- Hardened `display_menu()` to catch per-action `PasswordPromptError`, `SeedPassError`, and generic exceptions so failures no longer terminate the whole TUI session.
- Added graceful timeout-lock recovery messaging when unlock is cancelled/failed after inactivity timeout.
- Fixed incorrect call signature in Add Entry submenu header rendering (`clear_header_with_notification(...)` now receives `password_manager`).
- Added crash-regression coverage in `src/tests/test_cli_invalid_input.py` for action failures and timeout-unlock cancellation handling.

## Settings/Relay Submenu Hardening
- Added local exception guards in `handle_settings`, `handle_profiles_menu`, and `handle_nostr_menu` so submenu actions report failures and return control instead of crashing the TUI.
- Added explicit graceful handling for Settings -> Lock Vault unlock cancellations/failures.
- Corrected `clear_header_with_notification(...)` call signatures in settings-related submenus to pass `password_manager` as first argument.
- Added regression tests in `src/tests/test_settings_menu.py` for:
  - missing settings handler method
  - lock/unlock cancellation
  - profiles submenu action failure

## Import/Export + Nostr Workflow Guardrails
- Hardened settings menu options for export/import/TOTP export with explicit error messaging (`Export failed`, `Import failed`, `2FA export failed`) instead of generic crashes.
- Added graceful no-path handling for Settings -> Import (`No path entered.`).
- Hardened CLI subcommand entrypoints in `main.py`:
  - require `--file` for `export`/`import`
  - catch and report failures for `export`, `import`, `search`, `get`, and `totp` commands.
- Added regression tests for these cases in:
  - `src/tests/test_settings_menu.py`
  - `src/tests/test_cli_export_import.py`

## Installer Dependency Resolution Fix (2026-02-26)
- Root cause of installer failures was a stale `requirements.lock` pin (`cffi==1.17.1`) conflicting with `pynacl==1.6.2` (requires `cffi>=2.0.0` on Python >=3.9).
- A second hidden source issue blocked clean lock regeneration: `starlette>=0.49.1` was incompatible with `fastapi>=0.110` resolution path (current fastapi metadata requires `starlette<0.48`).
- Updated dependency sources to consistent constraints:
  - `src/requirements.txt`: `starlette>=0.40,<0.48`
  - `src/runtime_requirements.txt`: `starlette>=0.40,<0.48`
  - `pyproject.toml`: `starlette = ">=0.40,<0.48"`
- Regenerated `requirements.lock` with hashes; key resolved pins now include:
  - `cffi==2.0.0`
  - `pynacl==1.6.2`
  - `fastapi==0.116.1`
  - `starlette==0.47.3`
- Verified the installer-critical step succeeds in a fresh virtualenv:
  - `python -m pip install --require-hashes -r requirements.lock`

## TORCH Windows Checkout Fix (2026-02-26)
- Root cause: tracked TORCH artifact filenames used `:` in timestamps (e.g. `CONTEXT_2026-02-15T01:03:31Z.md`), which Windows cannot checkout.
- Confirmed scheduler/runtime already emits Windows-safe scheduler/memory filenames (`HH-mm-ss`), and backup folder names were already sanitized.
- Removed all tracked colon-variant duplicates under `torch/src/*` and `torch/_backups/*` where matching dash-variant files already existed.
- Validation: `git ls-files | rg ':'` now returns no results.

## TORCH Update + Windows Filename Validation (2026-02-26)
- Updated TORCH package to `1e3f88e` via tarball install, then ran `torch-lock update --force` and `npm install --prefix torch`.
- Quick validation passed: `npm run --prefix torch lock:check:daily -- --json --quiet` returned `lockCount: 0` with a full available roster.
- Windows compatibility check passed: `git ls-files | rg ':'` returned no tracked paths.

## GitHub Actions Poetry Cache Bootstrap Fix (2026-02-26)
-  with  requires  to already exist on PATH in that same step.
- In , Poetry was installed after setup-python via usage: pipx [-h] [--quiet] [--verbose] [--version]
            {install,uninject,inject,upgrade,upgrade-all,uninstall,uninstall-all,reinstall,reinstall-all,list,run,runpip,ensurepath,environment,completions}
            ...

Install and execute apps from Python packages.

Binaries can either be installed globally into isolated Virtual Environments
or run directly in a temporary Virtual Environment.

Virtual Environment location is /home/user/.local/share/pipx/venvs.
Symlinks to apps are placed in /home/user/.local/bin.
Symlinks to manual pages are placed in /home/user/.local/share/man.

optional environment variables:
  PIPX_HOME             Overrides default pipx location. Virtual Environments
                        will be installed to $PIPX_HOME/venvs.
  PIPX_BIN_DIR          Overrides location of app installations. Apps are
                        symlinked or copied here.
  PIPX_MAN_DIR          Overrides location of manual pages installations.
                        Manual pages are symlinked or copied here.
  PIPX_DEFAULT_PYTHON   Overrides default python used for commands.
  USE_EMOJI             Overrides emoji behavior. Default value varies based
                        on platform.

options:
  -h, --help            show this help message and exit
  --quiet, -q           Give less output. May be used multiple times
                        corresponding to the WARNING, ERROR, and CRITICAL
                        logging levels.
  --verbose, -v         Give more output.
  --version             Print version and exit

subcommands:
  Get help for commands with pipx COMMAND --help

  {install,uninject,inject,upgrade,upgrade-all,uninstall,uninstall-all,reinstall,reinstall-all,list,run,runpip,ensurepath,environment,completions}
    install             Install a package
    uninject            Uninstall injected packages from an existing Virtual
                        Environment
    inject              Install packages into an existing Virtual Environment
    upgrade             Upgrade a package
    upgrade-all         Upgrade all packages. Runs `pip install -U <pkgname>`
                        for each package.
    uninstall           Uninstall a package
    uninstall-all       Uninstall all packages
    reinstall           Reinstall a package
    reinstall-all       Reinstall all packages
    list                List installed packages
    run                 Download the latest version of a package to a
                        temporary virtual environment, then run an app from
                        it. Also compatible with local `__pypackages__`
                        directory (experimental).
    runpip              Run pip in an existing pipx-managed Virtual
                        Environment
    ensurepath          Ensure directories necessary for pipx operation are in
                        your PATH environment variable.
    environment         Print a list of environment variables and paths used
                        by pipx.
    completions         Print instructions on enabling shell completions for
                        pipx, causing CI bootstrap failure.
- Switched cache mode to  to avoid requiring Poetry during Python setup.
