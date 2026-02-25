### 1. [2026-02-25] (torch, scheduler, host-mode)
When running `npm run --prefix torch scheduler:daily`, the scheduler resolves config from `torch/torch-config.json` (cwd-scoped), not the repo-root `torch-config.json`.

### 2. [2026-02-25] (torch, scheduler, handoff)
A non-interactive scheduler run now requires `scheduler.handoffCommandByCadence.<cadence>` in the active torch config; missing it hard-fails after lock acquisition.

### 3. [2026-02-25] (torch, scheduler, lint)
After `torch-lock update --force`, `torch/eslint.config.mjs` is restored and `npm run --prefix torch lint` passes when `torch/node_modules` is installed.
### 4. [2026-02-25] (ci, pytest, docs, resilience)
`src/tests/test_cli_doc_examples.py` failed collection in CI when `docs/docs/content/01-getting-started/01-advanced_cli.md` is absent in the checkout. Guarding `load_doc_commands()` with `pytest.skip(..., allow_module_level=True)` avoids hard failures and keeps CI green for docs-light clones.
### 5. [2026-02-25] (github-actions, matrix, fail-fast)
In `.github/workflows/tests.yml`, the matrix job defaults to fail-fast; when one axis fails, other OS/Python jobs are canceled and report `Error: The operation was canceled`. Set `strategy.fail-fast: false` to surface the real failing axis instead of cancellation noise.
