# Operational Runbooks

This index tracks operational playbooks required by security readiness item #9.

## Incident Runbooks

- Relay health preflight and sync degradation:
  - `docs/agent-handoffs/incidents/2026-02-15-relay-health-preflight-job.md`

## Rollout/Recovery Runbooks

- Staged rollout and rollback drill:
  - `docs/staged_rollout_runbook.md`

## Operational Readiness Minimum

For each release cycle:
1. Execute at least one staged rollout drill from `docs/staged_rollout_runbook.md`.
2. Validate release artifact integrity using `docs/release_verification_runbook.md`.
3. Verify relay health preflight checks for active relays before broad rollout.
4. Log drill date, owner, and outcome in `docs/security_readiness_checklist.md`.
