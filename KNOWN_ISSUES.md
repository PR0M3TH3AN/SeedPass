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

### [Active] BIP85 Non-Standard Derivation Path
- **Symptoms**: `BIP85` uses `app_no=2` for symmetric key derivation instead of `128` (Hex) or `0` (BIP32).
- **Repro**: `src/local_bip85/bip85.py:derive_symmetric_key` uses default `app_no=2`.
- **Workaround**: None required; internal consistency is maintained.
- **Root Cause**: Implementation choice or legacy behavior.
- **Status**: Active (Documented in `PROTOCOL_INVENTORY.md` and `reports/protocol/protocol-report-2026-02-26.md`).
- **Last Checked**: 2026-02-26

### [Active] Missing Relay Health Preflight Job Incident Runbook
- **Symptoms**: `torch/TORCH.md` references an incident runbook (`docs/agent-handoffs/incidents/2026-02-15-relay-health-preflight-job.md`) that does not exist in the repository.
- **Repro**: `ls docs/agent-handoffs/incidents/2026-02-15-relay-health-preflight-job.md`
- **Workaround**: Manually investigate relay issues using `npm run lock:health`.
- **Root Cause**: Missing documentation file not committed or deleted.
- **Status**: Active (A placeholder was created on 2026-03-01 by `content-audit-agent`).
- **Last Checked**: 2026-03-01
