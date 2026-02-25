# SeedPass Threat Model (Draft v0.2)

## Scope

This draft covers SeedPass core vault operations, local storage, portable backups,
and Nostr synchronization paths.

## Security Objectives

1. Confidentiality of parent seed and derived secrets.
2. Integrity of vault/index data across local and synced states.
3. Reliable recovery from seed phrase and/or encrypted backup.
4. Deterministic derivation of artifacts across supported platforms/versions.

## Assets

1. Parent seed phrase.
2. Derived artifacts (passwords, TOTP secrets, key material).
3. Encrypted vault index (`seedpass_entries_db.json.enc` and equivalents).
4. Portable backup payloads and metadata.
5. Account metadata:
   - Fingerprints.
   - Relay configuration.
   - Sync state (manifest IDs, timestamps).

## Trust Boundaries

1. Local host boundary:
   - Application process, filesystem, clipboard, terminal.
2. Network boundary:
   - Nostr relay transport and storage (untrusted relays).
3. Backup boundary:
   - Exported files and any external backup path.
4. Build/dependency boundary:
   - Package dependencies, installers, and release artifacts.

## Attacker Profiles

1. Remote observer:
   - Can observe Nostr traffic metadata and timing; cannot break strong cryptography.
2. Malicious relay operator:
   - Can drop, reorder, replay, or withhold events; can inspect ciphertext and metadata.
3. Local unprivileged attacker:
   - Can read user-level files on a compromised host.
4. Local privileged attacker / malware:
   - Can inspect process memory, keypresses, clipboard, and runtime state.
5. Supply-chain attacker:
   - Can attempt dependency or build artifact compromise.

## Assumptions

1. Cryptographic primitives and libraries are implemented correctly.
2. User keeps parent seed secret and offline where possible.
3. Host OS is not fully compromised during sensitive operations.
4. Relay operators are untrusted for confidentiality/integrity.
5. Users can securely verify installation provenance.

## Non-Goals

1. Protection against a fully compromised endpoint with active malware.
2. Guaranteed metadata privacy from global traffic analysis.
3. Protection if the parent seed is disclosed.

## High-Risk Scenarios

1. Parent seed leakage:
   - Impact: total compromise of all deterministic artifacts.
   - Mitigations: strict secret handling, no logging, secure backup guidance.
2. Local plaintext leakage (logs/temp/clipboard):
   - Impact: credential theft despite encrypted-at-rest vault.
   - Mitigations: clipboard auto-clear, log redaction, temp file minimization.
3. Relay manipulation/replay/stale restore:
   - Impact: rollback or inconsistent state across devices.
   - Mitigations: checksum verification, manifest/delta integrity checks, explicit sync guidance.
4. Export backup mishandling:
   - Impact: offline brute-force or direct exposure if unencrypted export is used.
   - Mitigations: encrypted export default, warnings, permissions hardening.
5. Dependency/build compromise:
   - Impact: malicious code exfiltration of seed/secrets.
   - Mitigations: lockfiles + hashes, dependency audit, signed releases.

## Required Decisions (Item 1 Completion Gate)

1. Acceptable metadata leakage:
   - Are payload size/timing/fingerprint-derived identifiers acceptable for production use?
2. Endpoint compromise stance:
   - What user guidance is mandatory for host hardening and safe operation?
3. Recovery policy:
   - Which recovery path is canonical for production: seed-only, backup-only, or both?
4. Relay trust posture:
   - Minimum relay set diversity and failover recommendations.
5. Release trust chain:
   - Required artifact signing and verification process.

## Proposed Defaults

Status: `Approved (Provisional)`

1. Metadata leakage posture:
   - Proposed default: Accept ciphertext-size and sync-timing leakage as an
     explicit tradeoff for relay-based recovery.
   - Requirement: Document this clearly in user-facing security docs and warn
     users not to treat relay metadata as private.
   - Constraint: No plaintext secret material or deterministic secret-derived
     fields should be published to relays.

2. Endpoint compromise stance:
   - Proposed default: SeedPass is not secure against active local malware or
     a fully compromised host.
   - Requirement: Add explicit operational guidance:
     - Use dedicated, hardened device profile for high-value seeds.
     - Keep offline mode enabled unless sync is required.
     - Minimize clipboard usage for sensitive workflows.
   - Requirement: Add periodic hygiene checklist in docs.

3. Recovery policy:
   - Proposed default: Canonical recovery is seed-first; encrypted portable
     backup import is secondary for convenience and fast restore.
   - Requirement: Every release must preserve both:
     - seed-only deterministic recovery path
     - encrypted backup export/import compatibility
   - Requirement: Keep migration tests for legacy indexes and backup formats.

4. Relay trust posture:
   - Proposed default: Minimum 3 independent relays from different operators.
   - Requirement: Recommend at least 1 high-availability relay + 2 alternates.
   - Requirement: Treat relay data as untrusted input; require checksum and
     integrity validation before accepting restored data.
   - Requirement: Keep retry/backoff behavior for eventual consistency.

5. Release trust chain:
   - Proposed default: Signed tags/releases plus published checksums for all
     distributable artifacts.
   - Requirement: Dependency lockfile with hashes remains mandatory in CI.
   - Requirement: Reject release if provenance checks fail or lockfile drift is
     detected without review.

## Decision Approval Record

Use this table to convert proposed defaults to approved policy.

| Decision Area | Proposed | Approved | Date | Reviewer | Notes |
|---|---|---|---|---|---|
| Metadata leakage posture | Yes | Yes | 2026-02-25 | Maintainers (Provisional) | Accepted as explicit recovery tradeoff. |
| Endpoint compromise stance | Yes | Yes | 2026-02-25 | Maintainers (Provisional) | Not secure against active local malware. |
| Recovery policy | Yes | Yes | 2026-02-25 | Maintainers (Provisional) | Seed-first canonical recovery. |
| Relay trust posture | Yes | Yes | 2026-02-25 | Maintainers (Provisional) | Minimum 3 independent relays recommended. |
| Release trust chain | Yes | Yes | 2026-02-25 | Maintainers (Provisional) | Signed releases + checksums required. |

## Initial Risk Ranking

1. Critical: parent seed compromise.
2. High: endpoint malware/memory scraping.
3. High: insecure backup handling and accidental plaintext exposure.
4. Medium: relay replay/staleness causing wrong-state restore.
5. Medium: supply-chain compromise.

## Mapping to Existing Evidence

1. Real-relay restore/sync E2E coverage:
   - `src/tests/test_nostr_real.py`
2. Portable backup/import integrity tests:
   - `src/tests/test_portable_backup.py`
3. Account lifecycle roundtrip tests:
   - `src/tests/test_account_roundtrip_restore.py`
4. Large-index relay syncability probe:
   - `src/tests/test_nostr_index_size.py`

## Next Actions

1. Convert provisional approvals to formal release-policy signoff before external audit.
2. Add a risk register table with owner and target date per high-risk scenario.
3. Link resulting mitigations back to code/tests/docs in `docs/security_readiness_checklist.md`.
