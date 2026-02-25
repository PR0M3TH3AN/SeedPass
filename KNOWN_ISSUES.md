# Known Issues

This file tracks persistent, verifiable issues that affect the codebase or development workflow.
It is updated daily by the `known-issues-agent`.

## Status Definitions
- **Active**: Reproduces consistently. Needs fix or workaround.
- **Resolved**: Fixed and verified.
- **Unknown**: Cannot verify due to missing context/env.

## Issues

### [Resolved] Missing ESLint Configuration in `torch/`
- **Symptoms**: `npm run --prefix torch lint` fails with "ESLint configuration not found".
- **Repro**: `npm run --prefix torch lint`
- **Workaround**: Ensure `eslint.config.mjs` is present and `npm install` is run.
- **Root Cause**: `npm install` not run in restricted environments.
- **Status**: Resolved (verified by `known-issues-agent` on 2026-02-25).
- **Last Checked**: 2026-02-25

### [Resolved] Scheduler Configuration Missing Handoff Command
- **Symptoms**: Multiple agents failed with `Missing scheduler handoff command for non-interactive run`.
- **Repro**: `node bin/torch-lock.mjs check --cadence daily` without `torch-config.json` correctly populated.
- **Root Cause**: Missing or misconfigured `torch-config.json`.
- **Status**: Resolved (verified `torch-config.json` contains `handoffCommandByCadence` on 2026-02-25).
- **Last Checked**: 2026-02-25

### [Resolved] InnerHTML Usage in `landing/index.html`
- **Symptoms**: `style-agent` reported `innerHTML` violations.
- **Repro**: `grep "innerHTML" landing/index.html`
- **Workaround**: Refactor to use `textContent`.
- **Root Cause**: Unsafe DOM manipulation.
- **Status**: Resolved (verified file content on 2026-02-25).
- **Last Checked**: 2026-02-25
