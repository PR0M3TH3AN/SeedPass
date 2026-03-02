# Beta Hardening Report (2026-03-02)

## Scope
This report covers the hardening checklist run on branch `beta` after Textual TUI v2 parity/UX fixes.

## 1) CI-equivalent validation
Command:
- `PATH=".venv/bin:$PATH" scripts/run_ci_tests.sh`

Result:
- Passed.
- Determinism gate: passed (`43 passed, 950 skipped`).
- Full suite: passed (`977 passed, 16 skipped`).

## 2) Installer smoke tests
Commands:
- `bash scripts/installer_smoke_unix.sh beta tui`
- `bash scripts/installer_smoke_unix.sh beta both`

Result:
- Both smoke runs passed.
- `both` mode correctly skipped GUI install in headless environment and still completed successfully.

Notes observed:
- Installer reported stale `seedpass` launchers on PATH from previous local installs; install still completed.
- This is an environment hygiene warning, not an installer failure.

## 3) Parity bug-bash harness
Commands:
- `python scripts/ai_tui2_agent_test.py --scenario extended --verbose`
- `python scripts/ai_tui_agent_test.py --scenario extended --verbose`

Result:
- TUI v2 extended scenario: passed.
- Legacy TUI extended scenario: passed.

## 4) Included UX fixes validated in this hardening pass
- TUI v2 selected-entry state now stays synchronized with list navigation/highlight.
- Left pane command/help content no longer hard-clips; scrolling enabled.
- Sensitive reveal/QR confirmation paths now show explicit in-panel instructions.
- QR panel avoids wrapping distortion for ASCII QR output.

## Current release posture
- Hardening checklist items 1-3 are complete and green for this environment.
- No blocking failures identified in CI-equivalent, installer smoke, or parity harness checks.
- Remaining operational caution: clean up stale local launchers in user environments to reduce ambiguity about which `seedpass` executable is being run.
