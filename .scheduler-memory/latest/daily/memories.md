### 1. [2026-02-25] (scheduler, daily, store, insight)

### 1. [2026-02-25] (torch, init, reinstall)
If `npx --no-install torch-lock init --help` prints initialization prompts, it may be interactive; use `printf '\n' | npx --no-install torch-lock init --force` to accept defaults non-interactively in CI/agent runs.

### 2. [2026-02-25…

---

### 2. [2026-02-25] (scheduler, daily, store, insight)

### 1. [2026-02-25] (torch, scheduler, host-mode)
When running `npm run --prefix torch scheduler:daily`, the scheduler resolves config from `torch/torch-config.json` (cwd-scoped), not the repo-root `torch-config.json`.

### 2. [2026-02-25] (torch, scheduler, handoff)
A non-inter…

---

### 3. [2026-02-25] (scheduler, daily, store, insight)

### 1. [2026-02-25] (torch, scheduler, host-mode)
When running `npm run --prefix torch scheduler:daily`, the scheduler resolves config from `torch/torch-config.json` (cwd-scoped), not the repo-root `torch-config.json`.

### 2. [2026-02-25] (torch, scheduler, handoff)
A non-inter…

---

### 4. [2026-02-26] (scheduler, daily, retrieve)

Memory retrieval seed for daily :: scheduler memory retrieval

---

### 5. [2026-02-25] (scheduler, daily, retrieve)

Memory retrieval seed for daily :: scheduler memory retrieval