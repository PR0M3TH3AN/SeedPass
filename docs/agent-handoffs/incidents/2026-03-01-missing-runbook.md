# 2026-03-01-missing-runbook

1. Context: `torch/TORCH.md` documents an incident runbook (`docs/agent-handoffs/incidents/2026-02-15-relay-health-preflight-job.md`) on line 402 for resolving relay publishing failures.
2. Observation: The file `docs/agent-handoffs/incidents/2026-02-15-relay-health-preflight-job.md` does not exist in the repository.
3. Action taken: Documented the missing file in `KNOWN_ISSUES.md`; later created the runbook at `docs/agent-handoffs/incidents/2026-02-15-relay-health-preflight-job.md`.
4. Validation performed: Verified runbook now exists and is linked from `docs/operational_runbooks.md`.
5. Recommendation for next agents: Keep incident runbooks discoverable via `docs/operational_runbooks.md` and update references when adding new playbooks.
