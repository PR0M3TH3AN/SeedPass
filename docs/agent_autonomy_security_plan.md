# SeedPass Agent Autonomy Security Plan

## Goal
Implement a staged security architecture that enables autonomous agents to use SeedPass safely in production environments without relying on plaintext secrets or overly broad access.

## Program Structure
- Phase A: Foundation
  Add policy engine hardening, brokered auth, scoped tokens, redaction, and auditable access.
- Phase B: Guardrails
  Add approval gates, high-risk secret isolation, and deterministic export controls.
- Phase C: Operations
  Add posture tooling, rotation workflows, recovery hardening, and conflict-safe sync semantics.

## 1. Native Non-Interactive Auth Brokers
- Problem:
  Agent auth depends heavily on env vars and manual password flow.
- Implementation:
  Add an auth broker abstraction with providers:
  `env` (backward-compatible), `keyring` (OS-native), `command` (for HSM/YubiKey helpers).
  Add broker options to `seedpass agent init/get` and then `vault unlock`, `api start`.
  Add broker plugins for `pkcs11` and `yubikey` as optional modules later.
- Data/Config:
  `--auth-broker`, `--broker-service`, `--broker-account`, `--broker-command`.
- Security:
  Never persist broker-returned secrets; memory-only use.
- Tests:
  broker resolution, failure handling, per-profile account defaults.
- Acceptance:
  agent workflows can authenticate without password env vars by using keyring/broker commands.

## 2. Fine-Grained RBAC Per Profile
- Problem:
  Coarse kind-level permissions are insufficient.
- Implementation:
  Extend policy rules to enforce allow/deny by:
  entry path, label regex, kind, field, operation (`read/create/update/export`).
  Enforce in CLI agent commands, API endpoints, and service layer wrappers.
- Data/Config:
  `agent_policy.json` schema v2 with explicit operation matrix and precedence.
- Tests:
  policy precedence, deny overrides, path+field restrictions.
- Acceptance:
  deterministic policy decisions for every operation and entry field.

## 3. Short-Lived Scoped Tokens
- Problem:
  Long-lived static tokens increase blast radius.
- Implementation:
  Expand token store to support:
  scope lists, TTL, usage count, profile binding, optional IP/host binding, revocation reason.
  Add token introspection endpoint/command.
- Data/Config:
  `agent_tokens.json` versioned schema.
- Tests:
  expiry, revoke, scope denial, kind denial, reuse after exhaustion.
- Acceptance:
  all agent access can use revocable TTL-bound scoped credentials.

## 4. One-Time Secret Leases
- Problem:
  Secrets may be exposed repeatedly after retrieval.
- Implementation:
  Add lease records tied to token and resource:
  fetch-once or N-use, automatic invalidation, lease audit linkage.
  Optional server-side one-time retrieval IDs for API consumers.
- Tests:
  first-use success, second-use denial, race behavior under concurrency.
- Acceptance:
  one-time leases are enforced reliably under parallel access.

## 5. Policy-Enforced Redaction
- Problem:
  Secrets can leak through stdout/logging by default.
- Implementation:
  Make safe output mode default in agent/API.
  Redact by field policy with optional reveal override requiring permission.
  Add structured redaction markers.
- Tests:
  output snapshot tests for masked/unmasked modes.
- Acceptance:
  secrets are masked by default in automation logs.

## 6. Auditable Event Log
- Problem:
  Access traceability is weak without tamper evidence.
- Implementation:
  Keep append-only signed chain log.
  Add verifier command:
  `seedpass agent audit-verify`.
  Add export to JSONL with integrity proofs.
- Tests:
  chain continuity, tamper detection, clock skew handling.
- Acceptance:
  any log tampering is detectable; access events are attributable.

## 7. Approval Gates
- Problem:
  High-risk actions need step-up control.
- Implementation:
  Define gate policies for `export`, `reveal_parent_seed`, `private_key_retrieval`.
  Add approval plugins:
  local second factor, signed approval token, webhook approver.
  Add TTL and single-use approval grants.
- Tests:
  denied without approval, success with valid grant, grant expiry.
- Acceptance:
  risky operations cannot execute without valid step-up approval.

## 8. Secret-Class Isolation
- Problem:
  High-risk materials should not share unlock context with standard secrets.
- Implementation:
  Partition vault by class:
  standard vs high-risk (`seed`, `ssh`, `pgp`).
  Separate derived encryption keys and unlock factors.
  Per-class lock/unlock state.
- Data/Config:
  class partition metadata in encrypted config.
- Tests:
  class lock boundary, cross-class access denial.
- Acceptance:
  compromise of standard unlock path does not unlock high-risk partitions.

## 9. Agent Identities
- Problem:
  Tokens alone do not model lifecycle and ownership.
- Implementation:
  Add first-class agent accounts:
  id, owner, policy binding, rotation interval, revocation state.
  Tokens must be issued under agent identity.
- Data/Config:
  `agent_identities.json` versioned schema.
- Tests:
  identity disable/revoke, policy inheritance.
- Acceptance:
  every token and access event maps to a managed agent identity.

## 10. Safer Automation Primitives
- Problem:
  cron jobs often use plaintext env secrets.
- Implementation:
  Add job runner integration:
  broker-only auth, scoped policy binding, ephemeral runtime context.
  Add template commands for systemd timers and cron wrappers.
- Tests:
  non-interactive scheduled task success without plaintext secret files.
- Acceptance:
  supported scheduled workflows avoid plaintext env password dependence.

## 11. Recovery Hardening
- Problem:
  Recovery process can be brittle or under-tested.
- Implementation:
  Add Shamir split/recovery workflows for parent seed protection.
  Add scheduled backup verification drills with signed reports.
- Tests:
  split/recombine determinism, threshold enforcement, drill report generation.
- Acceptance:
  enforceable recovery posture with verifiable drills.

## 12. Conflict-Safe Sync Primitives
- Problem:
  multi-device edits can conflict unpredictably.
- Implementation:
  Introduce deterministic merge strategy:
  monotonic timestamps + deterministic tie-breaker + field-level merge rules.
  Encrypt metadata needed for conflict resolution.
- Tests:
  concurrent edit replay, deterministic final state across nodes.
- Acceptance:
  same inputs always produce same merged vault state.

## 13. Policy as Code
- Problem:
  policy lifecycle lacks strong review workflows.
- Implementation:
  Add schema validation, linting, canonical formatting, diff tooling, policy tests.
  Add optional signed policy bundles and hash pinning.
- Tests:
  lint failures, schema migration tests, canonical output tests.
- Acceptance:
  policy changes are reviewable, testable, and reproducible.

## 14. Deterministic Export Controls
- Problem:
  full-vault exports are dangerous for agent profiles.
- Implementation:
  Enforce policy-restricted subset exports:
  allowed kinds/paths/fields only, default deny full-vault for agent identities.
  Add deterministic manifest for exported subset.
- Tests:
  blocked full export, allowed subset export correctness.
- Acceptance:
  agent profiles cannot perform unrestricted exports by default.

## 15. Security Posture Tooling
- Problem:
  drift and misconfiguration can silently increase risk.
- Implementation:
  Add `seedpass agent posture-check`:
  stale credentials, weak broker config, overbroad policy rules, missing rotation, gate bypasses.
  Output machine-readable report and severity levels.
- Tests:
  posture check fixtures with expected findings.
- Acceptance:
  actionable posture report with CI-friendly nonzero exit on critical findings.

## Recommended Delivery Order
1. Item 1 completion across all auth entry points.
2. Items 2, 7, 14 enforcement expansion.
3. Items 3, 4, 9 identity-token lifecycle.
4. Items 6, 13, 15 governance and audit maturity.
5. Items 8, 10, 11, 12 deeper operational hardening.

## Definition of Done (Cross-Cutting)
- No plaintext secret persistence introduced.
- New schemas are versioned and migration tested.
- All new controls covered by unit + integration tests.
- CLI/API paths return deterministic, machine-readable error payloads.

## Help and Discoverability TODO Backlog
### Objective
Make SeedPass self-describing for autonomous agents and human operators so feature discovery does not depend on external docs or code spelunking.

### TODO 1: Login-Time Guidance
- Add concise post-unlock guidance text in:
  `seedpass vault unlock` and API `/api/v1/vault/unlock`.
- Include links/hints to:
  `seedpass --help`, `seedpass <group> --help`, API `/docs`.
- Add tests verifying hint visibility and stability.

### TODO 2: Machine-Readable Capability Surface
- Add `seedpass capabilities --format json|yaml|text`.
- Include:
  command groups, commands, option schema, auth modes, output mode (`json`/text), risk class, and policy gates.
- Ensure deterministic ordering for diffability in CI.

### TODO 3: Command Metadata Registry
- Add a central metadata registry for CLI/API capabilities.
- Fields:
  `name`, `summary`, `requires_unlock`, `supports_noninteractive`, `requires_approval`, `sensitive_outputs`, `policy_operations`.
- Generate help and capabilities output from the same registry to prevent drift.

### TODO 4: Agent-Focused Help Profile
- Add `--help-profile agent|human`.
- Agent profile:
  concise machine-actionable semantics, failure modes, deterministic examples, JSON schemas.
- Human profile:
  richer narrative hints and workflow examples.

### TODO 5: Output Schema Discovery
- Add `--output json` and `--describe-output` support to critical commands (`agent get`, `vault unlock`, token/policy commands).
- Publish expected JSON field schema in command help and capability output.

### TODO 6: Risk and Approval Annotations in Help
- Mark risky commands in help with a stable tag:
  `risk:high`, `approval:required`.
- Apply to:
  export, reveal-parent-seed, private key retrieval paths.

### TODO 7: Context Bootstrap Command for Agents
- Add `seedpass agent bootstrap-context`.
- Return:
  active profile fingerprint, policy status, broker options available, token status summary, feature support map, version info.

### TODO 8: API Discoverability Parity
- Ensure API endpoint metadata mirrors CLI capability data.
- Add a protected endpoint:
  `/api/v1/capabilities`.
- Keep OpenAPI tags aligned with CLI command groups.

### TODO 9: Regression Tests for Help Contracts
- Snapshot tests for:
  root help, group help, key command help, capabilities JSON.
- Add contract tests ensuring new commands include metadata fields.

### TODO 10: Documentation Sync Automation
- Add a CI check that compares:
  generated capabilities output vs docs command reference.
- Fail CI when command metadata and docs diverge.
