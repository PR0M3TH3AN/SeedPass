### 1. [2026-02-25] (torch, init, reinstall)
If `npx --no-install torch-lock init --help` prints initialization prompts, it may be interactive; use `printf '\n' | npx --no-install torch-lock init --force` to accept defaults non-interactively in CI/agent runs.

### 2. [2026-02-25] (torch, config, verification)
After reinstalling TORCH from the GitHub tarball, run `npx --no-install torch-lock check --cadence daily` to confirm the refreshed `torch-config.json` namespace and relay settings are valid.
