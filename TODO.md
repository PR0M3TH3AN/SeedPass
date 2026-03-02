# SeedPass TODO

This file tracks the remaining work from the latest bug search and security evaluation.

## Security

- [ ] Complete checklist item #8 (Supply chain and release integrity):
  - run one tagged release through `.github/workflows/release-integrity.yml` and link evidence in `docs/security_readiness_checklist.md`
  - resolve or formally time-box/own the `GHSA-wj6h-64fc-37mp` exception (`docs/supply_chain_release_integrity.md`)
  - enforce release/tag protections requiring `Release Integrity` + dependency audit checks
  - publish maintainer/consumer verification runbook (checksum + cosign verification with expected issuer/identity) ✅ `docs/release_verification_runbook.md`
- [ ] Upgrade vulnerable runtime dependencies in lockfiles and packaging inputs:
  - `aiohttp` -> `>=3.13.3`
  - `cryptography` -> `>=46.0.5`
  - `starlette` -> `>=0.49.1`
  - `python-multipart` -> `>=0.0.22`
  - `urllib3` -> `>=2.6.3`
  - `pynacl` -> `>=1.6.2`
  - `pillow` -> `>=12.1.1`
  - `orjson`, `pyasn1`, `cbor2` and other `pip-audit` findings
- [ ] Regenerate `requirements.lock` after upgrades and re-run the full test suite.
- [ ] Re-run `pip-audit -r requirements.lock` and ensure zero actionable runtime vulnerabilities.
- [ ] Evaluate the `Crypto.*` imports in `src/seedpass/core/password_generation.py` and either:
  - keep `pycryptodome` intentionally with explicit documentation, or
  - migrate RSA generation to `cryptography` APIs.

## Robustness

- [ ] Replace broad `except Exception: pass` blocks with explicit exceptions + logging:
  - `src/main.py`
  - `src/seedpass/core/manager.py`
  - `src/seedpass/core/menu_handler.py`
- [ ] Add telemetry-safe logs for swallowed error paths without exposing secrets.
- [ ] Harden startup/restore prompt flows against `EOFError` / cancellation loops:
  - startup options (`Continue` / `Restore from backup`)
  - restore-backup fingerprint/path prompts
  - ensure graceful return-to-menu instead of process-level failure.

## Tests To Add

- [ ] Add deterministic tests for `derive_pgp_key(..., key_type="rsa")` covering:
  - stable output across repeated runs
  - key fingerprint format and validity
- [ ] Add API rate-limit tests for:
  - per-client isolation
  - window expiry behavior
  - restart/reset behavior after `start_server()`
- [ ] Add API import tests for boundary conditions:
  - exactly-at-limit upload size
  - malformed multipart payload
  - invalid JSON body for path-based import
- [ ] Add regression tests for manager notification/logging fallback paths currently guarded by broad exception handling.

## Documentation

- [ ] Document API import upload limit (`SEEDPASS_MAX_IMPORT_BYTES`) in user docs.
- [ ] Add a security maintenance section describing dependency-audit cadence and update policy.
