# Release Verification Runbook

Purpose: provide maintainers and consumers a deterministic process to verify SeedPass release artifacts and signatures.

## Inputs

- Release assets downloaded from GitHub release:
  - `SHA256SUMS`
  - `SHA256SUMS.sig`
  - `SHA256SUMS.pem`
  - distribution artifacts (`dist/*.whl`, `dist/*.tar.gz`)
- Local checkout of this repository (for verifier script).

## 1) Verify artifact checksums

```bash
python scripts/release_integrity.py verify --checksum-file SHA256SUMS --base-dir .
```

Expected result: no mismatches and process exits `0`.

## 2) Verify keyless signature and certificate constraints

```bash
cosign verify-blob \
  --certificate SHA256SUMS.pem \
  --signature SHA256SUMS.sig \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/PR0M3TH3AN/SeedPass/.github/workflows/release-integrity.yml@refs/tags/.+$' \
  SHA256SUMS
```

Expected result:
- signature verification passes,
- certificate issuer is GitHub OIDC,
- certificate identity matches this repository `release-integrity.yml` workflow on a tag ref.

## 3) Verify release workflow provenance (maintainers)

1. Open the workflow run referenced by the release.
2. Confirm workflow name: `Release Integrity`.
3. Confirm job `verify-and-sign` succeeded.
4. Confirm uploaded assets include:
   - `dist/*`
   - `SHA256SUMS`
   - `SHA256SUMS.sig`
   - `SHA256SUMS.pem`

## 4) Failure handling

- If checksum verification fails:
  - treat artifacts as untrusted,
  - re-download release assets,
  - if mismatch persists, open security incident and halt rollout.
- If signature verification fails:
  - treat release as untrusted,
  - verify you used the exact release assets,
  - if still failing, open security incident and halt rollout.

## 5) Record evidence

For each release, record in `docs/security_readiness_checklist.md`:
- release tag,
- workflow run URL,
- verification executor/date,
- pass/fail status.
