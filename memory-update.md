# Memory Update — bug-reproducer-agent — 2026-02-27

## Key findings
- The `scheduler-flow.md` script execution failed due to a missing runner (`codex`).
- The automated `bug-reproducer-agent` prompt execution failed.
- Fallback manual investigation identified one active issue: `BIP85 Non-Standard Derivation Path` (using `app_no=2` instead of standard). This is documented in `KNOWN_ISSUES.md`.

## Patterns / reusable knowledge
- Future runs should verify the runner environment variables (`SCHEDULER_PROMPT_PATH`, `SCHEDULER_AGENT`, `SCHEDULER_CADENCE`) are set correctly before invoking `run-selected-prompt.mjs`.
- If the runner fails, manual fallback or alternative automation (e.g., Python script) is required.

## Warnings / gotchas
- `torch/scripts/agent/run-selected-prompt.mjs` depends on an external runner (`codex` or similar) which may not be available in all environments.
