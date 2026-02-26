# Supply Chain and Release Integrity

This document defines the release trust chain for SeedPass and provides the evidence expected by checklist item #8 in `docs/security_readiness_checklist.md`.

## Scope

- Dependency lock and hash integrity (`requirements.lock`).
- Vulnerability review process for runtime dependencies.
- Release artifact checksums and signing.

## Controls

1. Locked dependencies:
   - Dependencies are pinned and hash-locked in `requirements.lock`.
   - CI and release automation regenerate the lock file from `src/requirements.txt` and fail on drift.
   - `scripts/release_integrity.py check-lockfile` enforces that pinned entries and SHA-256 hashes are present.

2. CVE review:
   - `pip-audit` runs in CI (`.github/workflows/dependency-audit.yml`) and at release time (`.github/workflows/release-integrity.yml`).
   - Vulnerabilities must be remediated before release unless a temporary exception is documented with a tracked advisory ID and owner.
   - Current temporary exception: `GHSA-wj6h-64fc-37mp`.

3. Artifact integrity:
   - Release artifacts are built with `python -m build`.
   - `scripts/release_integrity.py generate` creates a deterministic `SHA256SUMS` manifest.
   - `scripts/release_integrity.py verify` re-checks artifacts against `SHA256SUMS`.
   - `SHA256SUMS` is signed in GitHub Actions using keyless `cosign`, producing:
     - `SHA256SUMS.sig`
     - `SHA256SUMS.pem`

## Release Workflow

Workflow: `.github/workflows/release-integrity.yml`

On every published GitHub release, the workflow:

1. Verifies lockfile integrity and lock drift.
2. Runs CVE audit on pinned dependencies.
3. Builds source/wheel artifacts.
4. Generates and verifies `SHA256SUMS`.
5. Signs `SHA256SUMS` with keyless `cosign`.
6. Uploads artifacts and integrity files to the GitHub release.

## Manual Verification

From a checkout that includes release assets:

```bash
python scripts/release_integrity.py verify --checksum-file SHA256SUMS --base-dir .
cosign verify-blob \
  --certificate SHA256SUMS.pem \
  --signature SHA256SUMS.sig \
  SHA256SUMS
```

## Evidence

- Workflow: `.github/workflows/release-integrity.yml`
- Tooling: `scripts/release_integrity.py`, `src/seedpass/release_integrity.py`
- Tests: `src/tests/test_release_integrity_utils.py`

## Remaining Work To Mark Checklist Item #8 Done

1. Execute at least one tagged production release through `.github/workflows/release-integrity.yml` and record the run URL/artifact links in `docs/security_readiness_checklist.md`.
2. Eliminate the temporary audit exception (`GHSA-wj6h-64fc-37mp`) or document formal risk acceptance with expiration date and owner.
3. Add branch/release protection so publishable tags require successful `Release Integrity` and `Dependency Audit` checks before release publication.
4. Add maintainer verification runbook for release consumers that includes:
   - `python scripts/release_integrity.py verify --checksum-file SHA256SUMS --base-dir .`
   - `cosign verify-blob --certificate SHA256SUMS.pem --signature SHA256SUMS.sig SHA256SUMS`
   - expected identity/issuer constraints for keyless signing.
