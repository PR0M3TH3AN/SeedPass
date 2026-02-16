# Daily Agent Scheduler Prompt

Use `scheduler-flow.md` as the authoritative scheduler procedure.

> **Shared contract (required):** Ensure each selected prompt run enforces [`Scheduler Flow → Shared Agent Run Contract`](scheduler-flow.md#shared-agent-run-contract-required-for-all-spawned-agents).

Canonical roster source: `roster.json` (`daily` key).

## Daily Cadence Configuration

- `cadence`: `daily`
- `log_dir`: `task-logs/daily/`
- `branch_prefix`: `agents/daily/`
- `prompt_dir`: `prompts/daily/`

## Daily Roster

| # | Agent Name | Prompt File |
|---|------------|-------------|
| 1 | audit-agent | `audit-agent.md` |
| 2 | ci-health-agent | `ci-health-agent.md` |
| 3 | const-refactor-agent | `const-refactor-agent.md` |
| 4 | content-audit-agent | `content-audit-agent.md` |
| 5 | decompose-agent | `decompose-agent.md` |
| 6 | deps-security-agent | `deps-security-agent.md` |
| 7 | design-system-audit-agent | `design-system-audit-agent.md` |
| 8 | docs-agent | `docs-agent.md` |
| 9 | docs-alignment-agent | `docs-alignment-agent.md` |
| 10 | docs-code-investigator | `docs-code-investigator.md` |
| 11 | innerhtml-migration-agent | `innerhtml-migration-agent.md` |
| 12 | known-issues-agent | `known-issues-agent.md` |
| 13 | load-test-agent | `load-test-agent.md` |
| 14 | log-fixer-agent | `log-fixer-agent.md` |
| 15 | onboarding-audit-agent | `onboarding-audit-agent.md` |
| 16 | perf-agent | `perf-agent.md` |
| 17 | protocol-research-agent | `protocol-research-agent.md` |
| 18 | scheduler-update-agent | `scheduler-update-agent.md` |
| 19 | style-agent | `style-agent.md` |
| 20 | test-audit-agent | `test-audit-agent.md` |
| 21 | todo-triage-agent | `todo-triage-agent.md` |
| 22 | torch-garbage-collection-agent | `torch-garbage-collection-agent.md` |
