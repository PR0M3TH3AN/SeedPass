# SeedPass Security Readiness Checklist

Status legend: `Not Started`, `In Progress`, `Blocked`, `Done`

| # | Area | Status | Owner | Evidence / Link |
|---|------|--------|-------|-----------------|
| 1 | Threat model (attacker profiles, trust boundaries, assumptions) | Done | Security / Core | `docs/threat_model.md` (provisional approvals recorded 2026-02-25) |
| 2 | Crypto and key management review | In Progress | Security / Core | `docs/crypto_key_management_review.md`, `src/tests/test_kdf_modes.py`, `src/tests/test_export_plaintext_policy.py` |
| 3 | Secret handling and local data exposure hardening | Not Started | Core | |
| 4 | Backup and restore integrity validation | In Progress | Core / QA | `src/tests/test_account_roundtrip_restore.py`, `src/tests/test_portable_backup.py` |
| 5 | Nostr sync security and resilience validation | In Progress | Core / QA | `src/tests/test_nostr_real.py`, `src/tests/test_nostr_index_size.py` |
| 6 | Auth, lock/unlock, and access-control hardening | Not Started | Core | |
| 7 | Testing gates and quality thresholds | In Progress | QA | `scripts/check_critical_coverage.py`, CI workflows |
| 8 | Supply chain and release integrity | Not Started | DevOps | |
| 9 | Operational readiness and incident runbooks | Not Started | Security / Ops | |
| 10 | External audit and staged production rollout | Not Started | Maintainers | |

## Exit Criteria Per Item

1. Threat model:
   - Assets, trust boundaries, and attacker capabilities documented.
   - Explicit assumptions and non-goals documented.
   - Top risks prioritized with mitigations and owners.

2. Crypto and key management:
   - Primitive/parameter review completed.
   - Nonce/key lifecycle reviewed.
   - Negative tests for corruption/tampering/wrong key path.

3. Secret handling:
   - No secret leakage in logs/temp files/exports by default.
   - Clipboard, memory lifetime, and file permission checks documented.

4. Backup/restore:
   - Seed-only recovery and encrypted export/import validated.
   - Corruption and checksum mismatch behavior validated.

5. Nostr:
   - Real-relay publish/retrieve/restore tested.
   - Failure modes (delay/outage/stale state) tested.

6. Auth/access:
   - Lock/unlock/timeout/quick unlock behavior reviewed with tests.

7. Testing gates:
   - Critical module coverage gates enforced.
   - Network and stress tests are opt-in and documented.

8. Supply chain:
   - Locked dependencies, CVE review process, signed artifacts/checksums.

9. Operational:
   - Incident playbooks and recovery drills documented.

10. External validation:
   - Independent audit completed.
   - Critical findings resolved before broad production use.

## How To Use

1. Update each row with current status and owner.
2. Attach concrete evidence links (PRs, test files, docs, reports).
3. Treat `Done` as requiring evidence for all exit criteria.
