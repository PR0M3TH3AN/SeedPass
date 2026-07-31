# SeedPass TODO

This file tracks the remaining work from the latest bug search and security evaluation.

## Entropy audit (2026-07-31)

[`docs/entropy_audit_2026-07-31.md`](docs/entropy_audit_2026-07-31.md) — RNG and
randomness-integration audit. **No predictable-fallback defect:** every non-deterministic secret
uses `os.urandom` / `secrets`, and the `random` module is not imported anywhere in non-test source.

**Read the compatibility constraint in that document before touching
`core/password_generation.py`.** Passwords are never stored — they are re-derived on demand from
`(seed, index, length, policy, gen_version)`. Entries now carry `gen_version`, and an absent field
means v1. **The rule is permanent: never alter the output of a version that already exists in the
wild.** v1 is frozen; a fix that changes derivation goes into a new version, never into an old one.
`src/tests/test_entropy_integrity.py` enforces this with 18 v1 vectors — a failure there is never
"update the expected value".

- [x] **M4 (done)** — v1 password vectors frozen, plus fail-closed RNG tests, in
      `src/tests/test_entropy_integrity.py` (26 tests, inside the `--determinism-only` CI gate).
      18 vectors cover every policy and both sides of the 32-byte stream-wrap boundary.
      Mutation-verified: removing `_balance_distribution` (M1), altering the `DeterministicStream`
      wrap (M3) and changing the character mapping (M2) each turn all 18 red; adding a
      hash-of-timestamp fallback to `generate_bip85_seed` turns the fail-closed test red.
      **M1/M2/M3 are now safe to attempt.**
- [x] **L1 (done)** — deleted the dead HKDF block in `_derive_password_entropy`, dropped the three
      now-unused imports (`HKDF`, `hashes`, `default_backend`), and corrected the docstrings that
      named HKDF instead of PBKDF2. Verified as a negative control: all 18 v1 vectors stayed green,
      confirming the harness does not produce false alarms on behaviour-preserving edits.
- [x] **M1 / M2 / M3 (done)** — password generation is now versioned. `gen_version` defaults to 1
      everywhere, so existing entries and every untouched caller keep deriving v1 byte-identically;
      new password entries are stamped `gen_version: 2`. v2 drops the forced equal-quarters class
      quota (M1), draws by rejection sampling (M2) from an unbounded HMAC-expanded stream (M3), and
      enforces only the policy minima — choosing donor positions from classes that have a surplus,
      so raising one minimum can no longer break another.

      Measured at length 16 over 200 samples: v1 produced **1** distinct class composition, v2
      produces **82**. Per-character entropy 6.42 → 6.53 bits against a 6.555 ceiling. Chi-square
      96.1 (df=93) confirms the modulo bias is gone; lag-32 repeat rate sits within one standard
      error of chance, confirming the repeating pad is gone.
- [ ] **Opt-in upgrade UX for existing entries** — a per-entry action that re-derives at v2, with a
      confirmation making the consequence unmissable ("this changes the password; update it at the
      site first"). Never bulk-migrate. Until this ships, existing entries stay on v1 by design.
- [ ] **L2** — master seed is `os.urandom(32)` reduced to a hardcoded 12-word (128-bit) mnemonic
      while derived seeds default to 24 words. Not a defect; offer 24 words at profile creation.
- [x] **L4 (code fixes done)** — `torch/` temp filename now uses `randomBytes(8)`; the
      `Math.random` value misnamed `nonce` in `relay-health.mjs` is now `probeSuffix` from
      `randomBytes(6)`.
- [ ] **⚠️ Decision needed: `torch/_backups/` holds 5240 tracked files** across six dated
      snapshots. Untracking is a large deletion, so it is not an audit side effect. Costs today:
      duplicates every security grep hit, and bare `node --test` in `torch/` discovers them and
      fails 18 tests from stale snapshot code (`npm test` uses explicit paths, so CI is unaffected).
      Separately: `torch/` has no `test/` directory in the repo, so its `npm test` cannot run as
      written.
- [x] **L5 (done)** — `dependency-audit.yml` generates and uploads a CycloneDX SBOM from
      `requirements.lock`. Verified with the real tool: CycloneDX 1.6, 96 components, crypto chain
      recorded at exact versions.

L3 (broad `except Exception` around crypto — these re-raise, so no silent fallback) overlaps the
Robustness item further down.

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
