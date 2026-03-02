# Staged Rollout and Rollback Drill Runbook

Purpose: provide an operational procedure for controlled release rollout and verified rollback.

## Preconditions

Before rollout:
1. `scripts/run_ci_tests.sh` passes.
2. `scripts/tui2_coverage_gate.sh` passes.
3. `Release Integrity` and `Dependency Audit` workflows pass for release commit/tag.
4. Artifact verification passes (`docs/release_verification_runbook.md`).

## Stage Plan

1. Stage 0: Internal maintainer validation
- Install from release artifacts in a clean environment.
- Run core smoke:
  - launch default UI,
  - launch legacy fallback,
  - verify vault unlock/read/search/edit/sync.

2. Stage 1: Limited beta audience
- Announce release to a small, known test cohort.
- Monitor incident channels for:
  - startup failures,
  - sync failures,
  - regression in retrieve/reveal/QR paths.

3. Stage 2: Broad availability
- Proceed only if no Sev1/Sev2 regressions are open from Stage 1.

## Rollback Trigger Criteria

Rollback immediately when any of the following occur:
- deterministic data-loss/corruption report is reproducible,
- critical auth/lock/unlock regression,
- release artifact integrity verification failure,
- sustained sync failure above acceptable operational threshold.

## Rollback Procedure

1. Stop broad rollout communications.
2. Revert default routing or publish patch with legacy fallback default.
3. Publish incident notice with:
   - affected versions,
   - user mitigation path,
   - expected follow-up timeline.
4. Open incident handoff note under `docs/agent-handoffs/incidents/`.

## Drill Recording Template

For each drill or production rollout:
- date:
- owner:
- release tag/commit:
- stage completed:
- pass/fail:
- rollback invoked (yes/no):
- incident reference (if any):
