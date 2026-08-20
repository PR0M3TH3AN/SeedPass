# Release Protection Policy

Purpose: define repository protection requirements so releases cannot be published without passing integrity and audit gates.

## Branch Protection (default branch)

Require pull requests for protected branches and require status checks to pass before merge.

Minimum required checks:
- `Tests / test (ubuntu-latest, 3.11)`
- `Dependency Audit / audit` (scheduled/manual job should also be runnable on demand)

## Tag/Release Protection

Publishable release tags must be created only from protected branch tips and must be gated by successful release integrity checks.

Required controls:
1. Restrict who can create matching release tags (maintainers only).
2. Require successful `Release Integrity / verify-and-sign` before release publication.
3. Require successful dependency audit for the same commit/tag.
4. Require signed commits/tags per org policy where available.

## Manual Enforcement Checklist (until fully automated in platform settings)

Before publishing any release:
1. Confirm commit is on protected branch tip.
2. Run `Release Integrity` workflow and verify success.
3. Run `Dependency Audit` workflow and verify success (or documented time-boxed exception).
4. Verify release asset signature/checksum steps using `docs/release_verification_runbook.md`.

## Evidence Recording

For each release, capture:
- release tag,
- protected branch commit SHA,
- workflow run URLs (`Release Integrity`, `Dependency Audit`),
- reviewer/approver identity,
- verification runbook executor.

Record evidence in `docs/security_readiness_checklist.md`.
