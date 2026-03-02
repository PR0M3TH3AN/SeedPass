# SeedPass Security Readiness Checklist

Status legend: `Not Started`, `In Progress`, `Blocked`, `Done`

| # | Area | Status | Owner | Evidence / Link |
|---|------|--------|-------|-----------------|
| 1 | Threat model (attacker profiles, trust boundaries, assumptions) | Done | Security / Core | `docs/threat_model.md` (provisional approvals recorded 2026-02-25) |
| 2 | Crypto and key management review | Done | Security / Core | `docs/crypto_key_management_review.md`, `src/tests/test_kdf_modes.py`, `src/tests/test_export_plaintext_policy.py` |
| 3 | Secret handling and local data exposure hardening | Done | Core | `docs/secret_handling_local_exposure_review.md`, `src/tests/test_memory_protection.py`, `src/tests/test_clipboard_utils.py`, `src/tests/test_fingerprint_encryption.py`, `src/tests/test_api_new_endpoints.py`, `src/tests/test_bip85_derivation_path.py` |
| 4 | Backup and restore integrity validation | In Progress | Core / QA | `src/tests/test_account_roundtrip_restore.py`, `src/tests/test_portable_backup.py` |
| 5 | Nostr sync security and resilience validation | In Progress | Core / QA | `src/tests/test_nostr_real.py`, `src/tests/test_nostr_index_size.py`, `src/tests/test_nostr_resilience_failure_modes.py` |
| 6 | Auth, lock/unlock, and access-control hardening | Done | Core | `docs/auth_lock_unlock_access_review.md`, `src/tests/test_api_new_endpoints.py`, `src/tests/test_vault_lock_flag.py`, `src/tests/test_inactivity_lock.py`, `src/tests/test_unlock_sync.py` |
| 7 | Testing gates and quality thresholds | In Progress | QA | `scripts/check_critical_coverage.py`, `scripts/tui2_coverage_gate.sh`, CI workflows |
| 8 | Supply chain and release integrity | In Progress | DevOps | `docs/supply_chain_release_integrity.md`, `docs/release_verification_runbook.md`, `docs/release_protection_policy.md`, `.github/workflows/release-integrity.yml`, `scripts/release_integrity.py`, `src/tests/test_release_integrity_utils.py` |
| 9 | Operational readiness and incident runbooks | In Progress | Security / Ops | `docs/operational_runbooks.md`, `docs/agent-handoffs/incidents/2026-02-15-relay-health-preflight-job.md` |
| 10 | External audit and staged production rollout | In Progress | Maintainers | `docs/staged_rollout_runbook.md` |

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

## Agent Autonomy Control Track (15-Item Plan)

Status legend: `Not Started`, `In Progress`, `Implemented`, `Validated`

| # | Control | Status | Evidence |
|---|---------|--------|----------|
| 1 | Native non-interactive auth brokers | Implemented | `src/seedpass/core/auth_broker.py`, `src/seedpass/cli/agent.py` (`--auth-broker` flows) |
| 2 | Fine-grained RBAC per profile | In Progress | `agent_policy.json` rule model (`operations`, `kinds`, `label_regex`, `path_regex`, `fields`) in `src/seedpass/cli/agent.py` |
| 3 | Short-lived scoped tokens | Implemented | `agent token-issue/list/revoke`, token TTL/use constraints in `src/seedpass/cli/agent.py` |
| 4 | One-time secret leases | Implemented | `agent get --lease-only`, `agent lease-consume/list/revoke` |
| 5 | Policy-enforced redaction | Implemented | `safe_output_default` and redaction fields in policy + agent output paths |
| 6 | Auditable event log | Implemented | `~/.seedpass/agent_audit.log` chained records, `agent audit-verify` |
| 7 | Approval gates | Implemented | `agent approval-issue/list/revoke`; enforced for export/reveal high-risk actions |
| 8 | Secret-class isolation | Implemented | `agent high-risk-factor-set/unlock/status/lock`, partition migration/store modules |
| 9 | Agent identities | Implemented | `agent identity-create/list/revoke`; token identity binding |
| 10 | Safer automation primitives | Implemented | `agent job-run`, job profiles, signed cron/systemd/API templates |
| 11 | Recovery hardening | Implemented | `agent recovery-split/recover/drill/drill-list` |
| 12 | Conflict-safe sync primitives | Implemented | deterministic merge + tombstones in `src/seedpass/core/sync_conflict.py` |
| 13 | Policy as code | Implemented | `agent policy-lint/review/apply` + `docs/policy_as_code.md` |
| 14 | Deterministic export controls | Implemented | policy-filtered export manifests + `agent export-check/export-manifest-verify` |
| 15 | Security posture tooling | Implemented | `agent posture-check/posture-remediate` with runtime config checks |

Notes:
- `Implemented` indicates feature availability in CLI/API paths and tests.
- `Validated` should be used after broader integration soak + external security review.

## How To Use

1. Update each row with current status and owner.
2. Attach concrete evidence links (PRs, test files, docs, reports).
3. Treat `Done` as requiring evidence for all exit criteria.
