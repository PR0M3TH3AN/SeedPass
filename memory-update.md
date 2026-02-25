### 1. [2026-02-25] (torch, scheduler, host-mode)
When running `npm run --prefix torch scheduler:daily`, the scheduler resolves config from `torch/torch-config.json` (cwd-scoped), not the repo-root `torch-config.json`.

### 2. [2026-02-25] (torch, scheduler, handoff)
A non-interactive scheduler run now requires `scheduler.handoffCommandByCadence.<cadence>` in the active torch config; missing it hard-fails after lock acquisition.

### 3. [2026-02-25] (torch, scheduler, lint)
After `torch-lock update --force`, `torch/eslint.config.mjs` is restored and `npm run --prefix torch lint` passes when `torch/node_modules` is installed.
