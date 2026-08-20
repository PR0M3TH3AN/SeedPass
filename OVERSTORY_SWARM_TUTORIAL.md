# SeedPass Overstory Swarm Runbook (Local Note)

Last verified: March 3, 2026  
Repo: `/home/user/Documents/GitHub/SeedPass`

This is a practical, repo-specific guide for running os-eco agent swarms in SeedPass.

## 1) Prerequisites

Required CLIs:
- `git`
- `tmux`
- `bun`
- `ov`
- `sd`
- `ml`
- `cn`
- `codex`

Quick check:

```bash
command -v bun && bun --version
command -v tmux && tmux -V
command -v ov && ov --version
command -v sd && sd --version
command -v ml && ml --version
command -v cn && cn --version
command -v codex && codex --version
```

Codex auth check:

```bash
codex login status || codex login
```

## 2) SeedPass-Specific Config That Must Be True

Check `.overstory/config.yaml`:
- `project.canonicalBranch: beta`
- quality gates should run Python checks:
  - `PATH=".venv/bin:$PATH" pytest -q`
  - `PATH=".venv/bin:$PATH" bash scripts/run_ci_tests.sh`
- `runtime.default: codex`
- leave top-level `models:` empty (important for Overstory `0.7.9`)

Check `.overstory/agent-manifest.json`:
- each agent `model` should be `gpt-5.3-codex`

Why this matters:
- In this environment, `codex exec --model sonnet` fails and exits immediately.
- That early exit causes Overstory to throw:
  - `Failed to send keys to tmux session "...": can't find pane: ...`

## 3) Prime Context at Start of Session

From repo root:

```bash
cd /home/user/Documents/GitHub/SeedPass
ml prime
sd prime
cn prime
```

## 4) Pick and Start a Task (Seeds)

```bash
sd ready
sd list --status=in_progress
sd list --status=open
sd show <ID>
sd update <ID> --status=in_progress
```

## 5) Start tmux Server Before Sling

Overstory needs tmux live before spawning:

```bash
tmux has-session -t ov-bootstrap 2>/dev/null || tmux new-session -d -s ov-bootstrap "bash"
```

If not running, Overstory may fail with:
- `Tmux server is not running (cannot reach session ...)`

## 6) Spawn Agents

Status first:

```bash
ov status --all --verbose
```

Spawn lead (hierarchy-compliant):

```bash
ov sling <SEEDPASS-ID> --capability lead --name lead-<short>
```

Spawn builder under lead:

```bash
ov sling <SEEDPASS-ID> --capability builder --name b1 --parent lead-<short> --depth 2
```

Quick debug bypass:

```bash
ov sling <SEEDPASS-ID> --capability builder --name b1 --runtime codex --force-hierarchy
```

Watch activity:

```bash
ov status --all --verbose
tmux ls | grep overstory
tmux capture-pane -pt overstory-SeedPass-b1:0.0 | tail -n 60
```

Attach manually:

```bash
tmux attach -t overstory-SeedPass-b1
```

Detach: `Ctrl-b d`

## 6.1) Monitor Agents (Second Terminal)

Open a second terminal in the repo and run one of these:

Snapshot status:

```bash
ov status --all --verbose
```

Live event stream:

```bash
ov feed --follow --interval 1000
```

Live dashboard UI:

```bash
ov dashboard --all
```

Inspect one agent continuously:

```bash
ov inspect <agent-name> --follow --interval 2000
```

Watch tmux sessions directly:

```bash
tmux ls | grep overstory
tmux capture-pane -pt overstory-SeedPass-<agent-name>:0.0 | tail -n 80
```

## 7) Common Failures and Fixes

### A) `can't find pane` during sling

Most likely in this repo: invalid model mapping.

Fix:
1. Set every agent model in `.overstory/agent-manifest.json` to `gpt-5.3-codex`.
2. Keep `.overstory/config.yaml` top-level `models:` empty.
3. Clean stale state and retry:

```bash
ov clean --worktrees --branches --sessions --all
ov sling <SEEDPASS-ID> --capability builder --name b1 --runtime codex --force-hierarchy
```

### B) `Tmux server is not running`

Fix:

```bash
tmux new-session -d -s ov-bootstrap "bash"
```

Then rerun sling.

### C) `branch ... already exists` or agent stuck as booting

Fix:

```bash
ov clean --worktrees --branches --sessions --all
```

Then retry with a fresh agent name if needed.

### D) `Coordinator cannot spawn "builder" directly`

Hierarchy is enforced. Either:
- spawn `lead` first and then spawn builder under lead, or
- use `--force-hierarchy` for quick debugging.

## 8) Merge and Close Workflow

After agent work is complete:

```bash
ov status --all --verbose
```

Run local quality gates on canonical branch before finalizing:

```bash
PATH=".venv/bin:$PATH" pytest -q
PATH=".venv/bin:$PATH" bash scripts/run_ci_tests.sh
```

Close task and sync trackers:

```bash
sd close <ID>
sd sync
ml learn
ml record <domain> --type <type> --description "..."
ml sync
cn sync
git push
```

## 9) Useful Recovery Commands

Stop one agent:

```bash
ov stop <agent-name>
```

Nuclear cleanup:

```bash
ov clean --worktrees --branches --sessions --all
```

Recommended default after every swarm run:

```bash
# stop any named agents from the run (if still active)
ov stop <agent-name> || true

# then fully reset overstory runtime state
ov clean --worktrees --branches --sessions --all

# verify empty
ov status --all --verbose
```

## 10) Known-Good Smoke Test

The following command path worked on March 3, 2026 in this repo:

```bash
tmux new-session -d -s ov-bootstrap "bash"
ov clean --worktrees --branches --sessions --all
ov sling SeedPass-95c5 --capability builder --name b1 --runtime codex --force-hierarchy
ov status --all --verbose
```

## 11) Running 10+ Agents Reliably

What worked in this repo:
- 10 tmux-backed Codex agent sessions launched in one run.
- Worktree agents successfully sent `ov mail` messages to coordinator.

Important caveats:
- Launching many `ov sling` commands at once can trigger SQLite contention (`database is locked`).
- Multiple builders on the exact same Seeds ID can be blocked by task-claim protection.

Recommended pattern:

```bash
# 1) clean start
ov clean --worktrees --branches --sessions --all
tmux has-session -t ov-bootstrap 2>/dev/null || tmux new-session -d -s ov-bootstrap "bash"

# 2) use one task per worker when possible
#    (or intentionally bypass checks only for controlled smoke tests)

# 3) stagger launches slightly (reduces lock contention)
for i in $(seq 1 10); do
  ov sling <TASK-ID-$i> --capability builder --name b$i --runtime codex --force-hierarchy
  sleep 0.4
done

# 4) monitor
ov status --all --verbose
ov feed --follow --interval 1000
```

If one launch fails with `database is locked`:

```bash
sleep 1
ov sling <TASK-ID> --capability builder --name <retry-name> --runtime codex --force-hierarchy
```
