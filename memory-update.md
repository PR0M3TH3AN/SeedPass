# Memory Update: changelog-agent run 2026-02-28

## Learnings
* The default branch is `beta`. `git log` should target `beta` instead of `main` when reading history for this repository.
* A `CHANGELOG.md` file exists and we append changes. Since no existing release notes dir was found, I created `releases/draft-YYYYMMDD.md`.
* We use `poetry run black .` for formatting tests properly, but I reverted the changes to `torch/scripts` formatting since they were not meant to be changed by this agent.

## Key findings
- The `scheduler-flow.md` script execution failed due to a missing runner (`codex`).
- The automated `bug-reproducer-agent` prompt execution failed.
- Fallback manual investigation identified one active issue: `BIP85 Non-Standard Derivation Path` (using `app_no=2` instead of standard). This is documented in `KNOWN_ISSUES.md`.

## Patterns / reusable knowledge
- Future runs should verify the runner environment variables (`SCHEDULER_PROMPT_PATH`, `SCHEDULER_AGENT`, `SCHEDULER_CADENCE`) are set correctly before invoking `run-selected-prompt.mjs`.
- If the runner fails, manual fallback or alternative automation (e.g., Python script) is required.

## Warnings / gotchas
- `torch/scripts/agent/run-selected-prompt.mjs` depends on an external runner (`codex` or similar) which may not be available in all environments.

# Memory Update — agent-security-foundation — 2026-03-01

## Key findings
- `src/seedpass/cli/agent.py` previously used a flat policy (`allow_kinds` / `deny_private_reveal`) with no rule-level operation, regex, or field matching.
- Introducing a versioned rule model can remain backward-compatible by auto-normalizing legacy policy files into structured `rules`.
- Empty `kinds` in deny rules must not be generated unintentionally for legacy migration, otherwise deny rules become wildcard blocks.

## Patterns / reusable knowledge
- For agent automation hardening, implement in this order for minimal breakage: policy normalization, enforcement hooks, safe-output redaction, token scoping/TTL/use limits, then append-only audit logging.
- Keep compatibility fields (`allow_kinds`, `deny_private_reveal`, `allow_export_import`) in the normalized policy output so older tooling still functions.
- Tests in `src/tests/test_cli_agent_mode.py` are the right place to cover agent policy regressions and token lease semantics.

## Warnings / gotchas
- CI environment may not have global `pytest`; use `./.venv/bin/pytest` in this repo.
- Agent command tests that monkeypatch `_load_policy` with legacy payloads require in-command normalization to avoid false policy denials.

# Memory Update — auth-broker-phase1 — 2026-03-01

## Key findings
- A dedicated broker abstraction in `seedpass/core/auth_broker.py` allows non-interactive secret retrieval without coupling broker logic into CLI command modules.
- Legacy env-var auth can remain default while enabling keyring/command brokers via explicit CLI options.
- For per-profile non-interactive unlock, defaulting keyring account to fingerprint in `agent get` avoids account collisions across profiles.

## Patterns / reusable knowledge
- Introduce broker modes in this order: `env` (compat), `keyring` (native OS storage), `command` (bridge to HSM/YubiKey helper tooling).
- Keep broker-specific failures converted to `typer.BadParameter` so automation receives consistent deterministic exit behavior.
- Agent-mode tests are the fastest place to validate broker migration without touching broader interactive flows.

## Warnings / gotchas
- `keyring` package is optional in current dependency set; keyring broker must fail with a clear install/error message when unavailable.
- Command broker output must be strictly stdout-only password text; any wrapper script should avoid additional logs on stdout.

# Memory Update — auth-broker-phase2 — 2026-03-01

## Key findings
- Extending broker-based auth to `vault unlock` and `api start` can be done without breaking interactive defaults by using `prompt` as the default broker.
- `api.start_server` can support non-interactive startup unlock by accepting an optional `unlock_password` parameter while preserving existing callers.

## Patterns / reusable knowledge
- For backward compatibility in CLI tests, keep existing command behavior unchanged unless explicit broker flags are provided.
- Use consistent broker options across commands: `--auth-broker`, `--password-env`, `--broker-service`, `--broker-account`, `--broker-command`.

## Warnings / gotchas
- When introducing additional args to helper functions used in tests (`start_server`), keep positional compatibility so existing monkeypatched fakes still work.

# Memory Update — capabilities-command-v1 — 2026-03-01

## Key findings
- Agents benefit from a single deterministic capability map command instead of scraping many `--help` screens.
- A stable JSON schema for capabilities is useful for automation and CI checks; text output can remain user-friendly.

## Patterns / reusable knowledge
- Implement capability output with fixed ordering and versioned schema (`schema_version`) to reduce churn in downstream parsers.
- Expose both CLI and API discovery hints in one surface so agents can bootstrap without external docs.

## Warnings / gotchas
- Capability maps can drift from actual commands if manually maintained; future work should generate metadata from command registries.

# Memory Update — bootstrap-context-v1 — 2026-03-01

## Key findings
- A dedicated `agent bootstrap-context` command significantly reduces setup overhead for autonomous agents by returning policy/token/auth posture in one deterministic JSON document.
- Treating invalid policy as non-fatal context (`policy.status=invalid`) is useful for diagnostics and recovery workflows.

## Patterns / reusable knowledge
- Bootstrap context should avoid all sensitive data and include only posture metadata and actionable command hints.
- `sort_keys=True` for JSON output improves reproducibility for automated parsers and snapshot tests.

## Warnings / gotchas
- Token posture summaries should classify revoked/expired/exhausted separately to avoid misleading “active” counts.

# Memory Update — posture-check-v1 — 2026-03-01

## Key findings
- A lightweight `agent posture-check` command can provide immediate security signal with deterministic output and CI-friendly exit behavior.
- Severity thresholding (`--fail-on`) is useful for phased rollout: start with `critical`, then tighten to `high`/`medium` as posture matures.

## Patterns / reusable knowledge
- Keep posture findings stable with explicit IDs and severities so automation can suppress or track specific controls over time.
- Treat invalid policy as a critical posture issue but still return full JSON payload for diagnostics.

## Warnings / gotchas
- Posture checks that read token store should classify revoked/expired/exhausted tokens separately to avoid false positives on active credentials.

# Memory Update — export-policy-gating-v1 — 2026-03-01

## Key findings
- Agent-profile export controls are easiest to roll out by introducing explicit context flags (`--agent-profile` / `X-SeedPass-Agent-Profile`) instead of changing default export behavior for all users.
- Full-vault export and subset export need separate controls; subset export can be deterministic by filtering encrypted index data by policy-allowed kinds before encryption.

## Patterns / reusable knowledge
- Centralize export control logic in a shared module (`seedpass/core/agent_export_policy.py`) so CLI and API enforcement remain consistent.
- For deterministic subset export payloads, use `json.dumps(..., sort_keys=True, separators=(",",":"))` before encryption.

## Warnings / gotchas
- Default policy currently allows `totp` in `allow_kinds`; denial tests must provide an explicit restrictive policy fixture when validating blocked TOTP export.

# Memory Update — export-reason-codes-audit-v1 — 2026-03-01

## Key findings
- Export policy denials are clearer for automation when returned as stable reason codes (`policy_deny:*`) rather than free-text strings.
- Recording explicit allow/deny export events in a dedicated signed audit log improves traceability without leaking secret material.

## Patterns / reusable knowledge
- Use shared policy evaluators (`evaluate_full_export`, `evaluate_kind_export`) across CLI and API to prevent decision drift.
- Keep denial code constants centralized in `agent_export_policy.py` so tests and clients can depend on stable semantics.

## Warnings / gotchas
- If using restrictive export tests for TOTP, ensure the policy fixture excludes `totp`, since default policy allows it.

# Memory Update — export-check-v1 — 2026-03-01

## Key findings
- A dedicated dry-run command (`agent export-check`) reduces failed export attempts and clarifies policy decisions before running sensitive operations.
- Optional strict non-zero exit (`--strict-exit`) is useful for CI/agent workflows without forcing failures for exploratory checks.

## Patterns / reusable knowledge
- Return deterministic JSON fields (`mode`, `allowed`, `reason`, `allow_kinds`) so agents can branch behavior without parsing free text.
- Reuse shared policy evaluators from `agent_export_policy.py` to keep check and enforcement decisions aligned.

## Warnings / gotchas
- `--mode kind` should require `--kind`; treat missing kind as input error, not policy denial.

# Memory Update — api-export-check-v1 — 2026-03-01

## Key findings
- API parity for dry-run export checks (`/api/v1/export/check`) lets headless agents preflight export permissions without invoking export operations.
- Returning HTTP 200 with `allowed=false` for policy denials (and 400 only for malformed input like missing kind/invalid mode) keeps control-flow predictable.

## Patterns / reusable knowledge
- Keep API and CLI preflight aligned by reusing shared evaluators from `agent_export_policy.py`.
- Include preflight endpoint in capability discovery output so agents can find it automatically.

## Warnings / gotchas
- `mode=kind` should reject missing `kind` via explicit `missing_kind` error code to avoid ambiguous denial semantics.

# Memory Update — filtered-export-manifest-v1 — 2026-03-01

## Key findings
- Policy-filtered exports benefit from an embedded deterministic `_export_manifest` that captures policy stamp, allowed kinds, redaction fields, and included/excluded entry counts.
- The same manifest builder should be reused by CLI and API filtered exports to avoid divergence.

## Patterns / reusable knowledge
- Keep manifests deterministic by excluding timestamps and sorting keys/indexes.
- Include a hash-based `policy_stamp` derived from canonical policy controls to support reproducibility and audit correlation.

## Warnings / gotchas
- Changes introducing JSON processing in API or tests require explicit `import json`; missing imports can surface as runtime failures in async route tests.

# Memory Update — export-manifest-verify-v1 — 2026-03-01

## Key findings
- Manifest verification should compare against the current normalized policy controls (not minimal export-only policy fields) to prevent false trust in stale or partial policy states.
- A strict-exit toggle supports both CI gating and exploratory diagnostics.

## Patterns / reusable knowledge
- Use stable error identifiers (`policy_stamp_mismatch`, `allow_kinds_mismatch`, `included_entry_indexes_mismatch`) to make verification machine-actionable.
- Keep verification input as plaintext JSON package to avoid coupling verifier with key management/decryption paths.

## Warnings / gotchas
- Tests that build and verify manifests must ensure both generator and verifier resolve policy from the same `APP_DIR` context.

# Memory Update — api-manifest-verify-v1 — 2026-03-01

## Key findings
- API parity for manifest verification (`/api/v1/export/manifest/verify`) enables headless agents to validate filtered export packages without shell access.
- Returning verification results as HTTP 200 with `valid` + `errors` simplifies client control flow compared to mixed status-code semantics.

## Patterns / reusable knowledge
- Reuse shared verification primitives from `agent_export_policy.py` across CLI and API to guarantee identical validation logic.
- Add new verification endpoints to `capabilities` discovery output so automation can discover them without hardcoded paths.

## Warnings / gotchas
- Policy mismatch tests should mutate `agent_policy.json` after package generation to ensure `policy_stamp_mismatch` is exercised reliably.
- Implemented approval-gate groundwork (Item 7) for agent-risk export workflows.
- Added `seedpass.core.agent_approval` helpers for approval issue/list/revoke/consume with TTL, use limits, and revocation persisted in `~/.seedpass/agent_approvals.json` (0600 perms).
- Added policy helper `approval_required(policy, action)` and wired policy parsing of `approvals.require_for` through export-policy loading.
- Added agent CLI commands: `agent approval-issue`, `agent approval-list`, `agent approval-revoke` and exposed these in bootstrap-context command discovery.
- Enforced step-up approval for full vault export when policy requires `export`:
  - CLI: `seedpass vault export --agent-profile --approval-id <id>`
  - API: `POST /api/v1/vault/export` with header `X-SeedPass-Approval-Id`.
- Denials now return policy reasons (`policy_deny:approval_required` or consumed-approval failures) and are logged through export policy audit events.
- Updated capabilities map to include approval commands and `X-SeedPass-Approval-Id` as a sensitive header.
- Added tests for approval issue/list/revoke plus CLI/API full-export approval gating; targeted suites passing:
  - `src/tests/test_cli_agent_mode.py` (27 passed)
  - `src/tests/test_typer_cli.py` (43 passed)
  - `src/tests/test_api_new_endpoints.py` (41 passed)
- Extended approval gates (Item 7 scope) beyond export:
  - CLI `vault reveal-parent-seed` now supports `--agent-profile` + `--approval-id` and enforces policy `approvals.require_for` for `reveal_parent_seed`.
  - API `POST /api/v1/vault/backup-parent-seed` now supports `X-SeedPass-Agent-Profile` + `X-SeedPass-Approval-Id` and enforces approval for `reveal_parent_seed` when configured.
- Expanded agent private retrieval path:
  - `agent get` accepts `--approval-id`.
  - Added private-kind retrieval support for `seed`, `managed_account`, `ssh`, `pgp`, `nostr` with policy/tokens/redaction pipeline.
  - Enforced `private_key_retrieval` approval requirement for private kinds with consume-on-use approvals.
- Updated capabilities map high-risk operations to reflect agent sensitive retrieval and backup-parent-seed API path.
- New/updated tests passed:
  - `src/tests/test_cli_agent_mode.py` (28 passed)
  - `src/tests/test_typer_cli.py` (45 passed)
  - `src/tests/test_api_new_endpoints.py` (43 passed)
- Implemented Item 4 one-time secret leases as first-class agent capability.
- Added `src/seedpass/core/agent_secret_lease.py` with versioned lease store, TTL/use-limit enforcement, revocation, and cross-process locking via `utils.file_lock.exclusive_lock`.
- Added agent lease commands:
  - `agent get --lease-only --ttl <sec> --lease-uses <n>` issues a resource-bound lease without returning secret.
  - `agent lease-consume <lease_id>` consumes one use and returns secret (policy + redaction applied).
  - `agent lease-list`, `agent lease-revoke` for lease lifecycle management.
- Lease records are tied to fingerprint/resource and optionally token id metadata; no plaintext secret material is persisted in lease store.
- Updated `agent bootstrap-context` command registry to include lease operations.
- Updated capabilities map to advertise lease support.
- Added regression tests:
  - Lease issue/consume/exhaust flow in `src/tests/test_cli_agent_mode.py`.
  - Capabilities JSON includes `security_features.leases` in `src/tests/test_typer_cli.py`.
- Verified passing suites:
  - `src/tests/test_cli_agent_mode.py` (29 passed)
  - `src/tests/test_typer_cli.py` (45 passed)
  - `src/tests/test_api_new_endpoints.py` (43 passed)
- Implemented Item 9 agent identities with lifecycle management and token binding.
- Added `src/seedpass/core/agent_identity.py` (versioned identity store) with create/list/get/revoke/ensure/active helpers.
- Added new agent CLI commands:
  - `agent identity-create --id ... --owner ... --policy-binding ... --rotation-days ...`
  - `agent identity-list [--show-revoked]`
  - `agent identity-revoke <id>`
- Bound new token issuance to identities:
  - `agent token-issue` now supports `--identity-id` (default `default-agent`) and auto-creates default identity as needed.
  - Token records include `identity_id`.
- Enforced identity state at token use time:
  - `_validate_token` now denies with `token_identity_revoked` when token identity is revoked/missing.
- Updated bootstrap context and capabilities to advertise identity features/commands.
- Added posture findings:
  - `tokens_missing_identity`
  - `tokens_for_revoked_identity`
- Added/updated tests in `src/tests/test_cli_agent_mode.py` and `src/tests/test_typer_cli.py`:
  - identity create/list/revoke
  - token denied after identity revocation
  - bootstrap/capabilities include identity command surface
- Verified test suites:
  - `src/tests/test_cli_agent_mode.py` (31 passed)
  - `src/tests/test_typer_cli.py` (45 passed)
  - `src/tests/test_api_new_endpoints.py` (43 passed)
- Started Item 8 secret-class isolation with a separate high-risk unlock factor/session for agent workflows.
- Added `src/seedpass/core/agent_secret_isolation.py`:
  - stores hashed high-risk factor (`agent_high_risk_factor.hash`),
  - manages per-fingerprint high-risk unlock sessions with TTL (`agent_high_risk_unlock.json`),
  - uses `exclusive_lock` for concurrency-safe session updates.
- Extended agent policy schema normalization to include `secret_isolation`:
  - `enabled` (bool),
  - `high_risk_kinds` (subset of private kinds),
  - `unlock_ttl_sec` (>=1).
- Added new agent CLI commands:
  - `agent high-risk-factor-set`
  - `agent high-risk-unlock`
  - `agent high-risk-status`
  - `agent high-risk-lock`
- Enforced secret isolation in access paths:
  - `agent get` denies private/high-risk retrieval with `policy_deny:high_risk_locked` unless unlocked,
  - `agent lease-consume` applies same high-risk lock check for private kinds.
- Updated bootstrap context and capabilities to advertise secret isolation command surface/features.
- Added/updated tests:
  - integrated private-kind lock/unlock flow test in `src/tests/test_cli_agent_mode.py`,
  - bootstrap context assertions include secret isolation commands,
  - capabilities JSON assertions include `security_features.secret_isolation`.
- Verified suites passing after changes:
  - `src/tests/test_cli_agent_mode.py` (32 passed)
  - `src/tests/test_typer_cli.py` (45 passed)
  - `src/tests/test_api_new_endpoints.py` (43 passed)
- Continued Item 8 by extending secret-class isolation beyond agent-only retrieval into broader CLI/API high-risk flows.
- Non-agent CLI enforcement updates:
  - `vault reveal-parent-seed` now checks high-risk isolation lock when policy isolation is enabled for `seed` and a high-risk factor is configured.
  - `vault export` now checks high-risk isolation lock under the same conditions before full export.
- API high-risk session endpoints added in `src/seedpass/api.py`:
  - `GET /api/v1/high-risk/status`
  - `POST /api/v1/high-risk/unlock` (requires token + password + `X-SeedPass-High-Risk-Factor`)
  - `POST /api/v1/high-risk/lock`
- API high-risk enforcement updates:
  - `/api/v1/vault/export` enforces high-risk unlocked session when export mode/policy includes isolated high-risk kinds.
  - `/api/v1/vault/backup-parent-seed` enforces high-risk unlocked session for `seed` when isolation applies.
- Extended export policy parser (`agent_export_policy.load_export_policy`) to support `secret_isolation` fields so API-side isolation decisions are policy-driven.
- Capabilities map now advertises new high-risk API endpoints and `X-SeedPass-High-Risk-Factor` sensitive header.
- Added regression tests:
  - CLI: reveal-parent-seed blocked when high-risk locked.
  - API: high-risk unlock/status/lock endpoints, export blocked when high-risk locked, backup-parent-seed blocked when high-risk locked.
- Verified passing targeted suites:
  - `src/tests/test_typer_cli.py` (46 passed)
  - `src/tests/test_api_new_endpoints.py` (46 passed)
  - `src/tests/test_cli_agent_mode.py` (32 passed)
- Advanced Item 8 toward vault/service-layer coverage by adding explicit partition metadata + retrieval gating.
- Added secret-class partition metadata defaults and helpers to `ConfigManager`:
  - default `secret_class_partitions` with `standard` and `high_risk` classes,
  - helpers: `get_secret_class_partitions`, `set_secret_class_partitions`, `set_partition_unlock_state`, `is_partition_unlocked`.
- API service-layer hardening in `src/seedpass/api.py`:
  - `/api/v1/high-risk/unlock` and `/api/v1/high-risk/lock` now update config partition unlock state (best-effort),
  - `/api/v1/entry/{id}` now enforces high-risk isolation for private kinds (`seed/ssh/pgp/nostr/managed_account`) using policy + session state.
- Policy parsing hardening in `agent_export_policy`:
  - `load_export_policy` now parses `secret_isolation` block (enabled/high_risk_kinds/unlock_ttl_sec) for API-side decisions,
  - policy stamp includes secret isolation fields.
- Added API regression test for private entry retrieval isolation:
  - blocked while high-risk locked,
  - allowed after `/api/v1/high-risk/unlock`.
- Re-verified key targeted suites after changes:
  - `src/tests/test_api_new_endpoints.py` (47 passed)
  - `src/tests/test_typer_cli.py` + `src/tests/test_cli_agent_mode.py` (78 passed combined)
- Continued Item 8 with explicit class-partition metadata and deeper service-layer enforcement.
- Added partition metadata defaults + helpers in `ConfigManager`:
  - `secret_class_partitions` default includes `standard` and `high_risk` classes,
  - helper methods for reading/updating partition metadata and unlock state.
- API high-risk unlock/lock endpoints now persist partition unlock state (best-effort) via config manager.
- Added retrieval-layer isolation enforcement in API:
  - `/api/v1/entry/{id}` checks entry kind and denies with `policy_deny:high_risk_locked` for private kinds when high-risk session is locked.
- Added regression test for API retrieval gating:
  - private entry blocked while locked,
  - allowed after high-risk unlock.
- Re-ran targeted suites successfully:
  - `src/tests/test_api_new_endpoints.py` + `src/tests/test_typer_cli.py` + `src/tests/test_cli_agent_mode.py` (125 passed combined)
  - `src/tests/test_core_api_services.py` + `src/tests/test_password_change.py` + `src/tests/test_kdf_strength_slider.py` (55 passed combined)
- Strengthened Item 8 isolation model from hash-check to cryptographic partition-key envelope.
- Updated `agent_secret_isolation`:
  - high-risk factor setup now generates a random partition key and stores it wrapped in `agent_high_risk_partition.key.enc.json` using factor-derived key (PBKDF2-SHA256 + Fernet envelope).
  - `verify_high_risk_factor` now validates by decrypting envelope (legacy hash fallback retained if envelope absent).
  - Added `unwrap_high_risk_partition_key`, `partition_key_tag_for_factor`, and session storage of `partition_key_tag` on unlock grants.
- Updated unlock flows to require envelope unwrap success before granting session:
  - CLI `agent high-risk-unlock` computes/stores partition key tag.
  - API `/api/v1/high-risk/unlock` computes/stores partition key tag.
- Existing policy/session isolation enforcement remains in place; now backed by cryptographic factor proof rather than plain hash compare.
- Verified suites after envelope change:
  - `src/tests/test_cli_agent_mode.py` + `src/tests/test_api_new_endpoints.py` (79 passed combined)
  - `src/tests/test_typer_cli.py` (46 passed)
  - `src/tests/test_core_api_services.py` + `src/tests/test_password_change.py` + `src/tests/test_kdf_strength_slider.py` (55 passed combined)

# Memory Update — secret-isolation-partition-migration-v1 — 2026-03-01

## Key findings
- Added an encrypted high-risk partition store (`src/seedpass/core/high_risk_partition_store.py`) that migrates private/high-risk entries out of the primary index into `seedpass_high_risk_entries.json.enc` and leaves deterministic stubs in index.
- High-risk factor handling now supports a wrapped partition key envelope (`agent_high_risk_partition.key.enc.json`) so unlock sessions can carry a partition key tag for partition reads.
- `agent lease-consume` needed explicit partition hydration for private kinds; without this, partitioned entries could fail downstream secret resolution.

## Patterns / reusable knowledge
- Keep partition access behind existing high-risk unlock checks and session TTLs; use the unlock session as the only source of partition key tag context.
- Add command-level migration (`agent high-risk-partition-migrate`) before enforcing partition-only retrieval to keep rollout safe for existing profiles.
- Regression tests for partition flows are most reliable in `src/tests/test_cli_agent_mode.py` by monkeypatching hydration and migration seams.

## Warnings / gotchas
- Any path that reads private entries by index must hydrate `partition=high_risk` stubs before attempting kind-specific secret derivation.
- API/CLI behavior can diverge if one retrieval path is updated without the other; keep partition rules centralized where possible.
- Added API parity for partition hydration in `GET /api/v1/entry/{id}` so `partition=high_risk` stubs are resolved via unlock-session key tag before response.
- Added API regression `test_get_entry_hydrates_partitioned_high_risk_entry` to lock this behavior.

# Memory Update — automation-primitives-v1 — 2026-03-01

## Key findings
- Added `agent job-run` as a schedule-safe wrapper over `agent get` with safe broker defaults (`keyring`/`command`) and explicit denial for `env` broker unless `--allow-env-broker` is passed.
- Added `agent job-template` to generate deterministic cron/systemd snippets that avoid plaintext password env requirements and encode brokered auth usage.
- Tightened token validation so legacy tokens without `identity_id` are denied at use time with `token_identity_missing`.

## Patterns / reusable knowledge
- Reusing `ctx.invoke(agent_get, ...)` keeps policy, redaction, approval, leases, and auditing semantics consistent across interactive and automated retrieval paths.
- Expose automation controls in both bootstrap-context command maps and capabilities output to keep discovery parity for autonomous agents.

## Warnings / gotchas
- Existing legacy tokens with empty `identity_id` now fail; rotate/reissue with `agent token-issue --identity-id ...` before enabling strict automation workflows.

# Memory Update — automation-job-profiles-v1 — 2026-03-01

## Key findings
- Added persistent automation job profiles in `src/seedpass/core/agent_job.py` with create/list/get/revoke lifecycle and 0600 on-disk storage.
- Added agent CLI commands: `job-profile-create`, `job-profile-list`, `job-profile-run`, and `job-profile-revoke` to support reusable scheduled workflows with policy-binding metadata.
- `job-profile-run` now executes through `agent job-run`, preserving existing policy/redaction/approval semantics while enforcing fingerprint binding.

## Patterns / reusable knowledge
- For safer automation rollout, keep reusable job metadata separate from token/secret material and route execution through existing guarded retrieval commands.
- Include automation profile capabilities in both `bootstrap-context` and `capabilities` output so agents can discover the full control surface deterministically.

## Warnings / gotchas
- `job-profile-run` enforces fingerprint match; invoking with a different `--fingerprint` intentionally denies.
- Command-broker job profiles must include `--broker-command` at creation time.
- Item 10 hardening continued with job profile policy/host guardrails.
- `agent job-profile-create` now stores `policy_stamp` (from current normalized policy) and `host_binding` (default current hostname).
- `agent job-profile-run` now denies by default on:
  - `job_profile_policy_mismatch` (active policy stamp drift)
  - `job_profile_host_mismatch` (host binding mismatch)
  with explicit override flags `--allow-policy-drift` and `--allow-host-mismatch`.
- Added `agent job-profile-check` command for profile posture checks (unsafe broker, policy drift, host mismatch, staleness) with optional strict exit.
- Updated capabilities/bootstrapped command maps to include `job-profile-check` and automation guardrail metadata.
- Added regression tests for policy mismatch, host mismatch, and profile check drift findings.
- Added API parity for automation job profiles (Item 10) in `src/seedpass/api.py`:
  - `GET/POST /api/v1/agent/job-profiles`
  - `DELETE /api/v1/agent/job-profiles/{job_id}`
  - `POST /api/v1/agent/job-profiles/{job_id}/run`
  - `GET /api/v1/agent/job-profiles/check`
- API run endpoint enforces profile fingerprint binding, policy-stamp drift checks, and host-binding checks with explicit override flags, and issues secret leases for matched resources.
- Capabilities discovery now includes new API job-profile endpoints.
- Added API regression tests for CRUD and run behavior (including policy drift denial + override).
- Added API template rendering endpoint for job profiles: `GET /api/v1/agent/job-profiles/{job_id}/template` with deterministic `cron` and `systemd` output modes.
- Endpoint supports profile/default/provided schedule resolution and returns command + rendered template payload for orchestration tooling.
- Added API regression coverage for cron and systemd template outputs.
- Updated capabilities API discovery list to include the new template endpoint.
- Added API template authoring + integrity workflows for automation jobs:
  - `POST /api/v1/agent/job-profiles/{job_id}/template` (richer template input)
  - `POST /api/v1/agent/job-profiles/{job_id}/template/verify` (manifest verification)
- Added signed template manifests (HMAC-SHA256) including template hash, policy stamp, host binding, and job profile id.
- Added deterministic template helpers shared by GET/POST template endpoints.
- Updated capabilities metadata/discovery with API template + verify endpoints and automation manifest-signing capability.

# Memory Update — recovery-hardening-v1 — 2026-03-01

## Key findings
- Added deterministic Shamir split/recover primitives in `src/seedpass/core/agent_recovery.py` (`split_secret`, `recover_secret`) with share token checksums.
- Added signed backup verification drill logging (`record_recovery_drill`, `list_recovery_drills`) with chained HMAC signatures.
- Exposed recovery workflows in agent CLI:
  - `agent recovery-split`
  - `agent recovery-recover`
  - `agent recovery-drill`
  - `agent recovery-drill-list`

## Patterns / reusable knowledge
- Recovery commands should default to non-revealing output and require explicit `--reveal` for plaintext recovery output.
- Drill reporting should be append-only and signed so verification history remains tamper-evident.

## Warnings / gotchas
- Current split derivation is deterministic by design for reproducibility; rotating labels should be treated as distinct recovery sets.
- Added Item 11 API parity for recovery workflows:
  - `POST /api/v1/agent/recovery/split`
  - `POST /api/v1/agent/recovery/recover`
  - `POST /api/v1/agent/recovery/drill`
  - `GET /api/v1/agent/recovery/drills`
  - `POST /api/v1/agent/recovery/drills/verify`
- Added drill-chain verification primitive in `agent_recovery.verify_recovery_drills` to detect tampering via chained HMAC signatures.
- Updated capabilities discovery to include new recovery API endpoints.
- Added API tests for split/recover roundtrip, drill list/verify, and tamper detection.

# Memory Update — conflict-safe-sync-v1 — 2026-03-01

## Key findings
- Introduced deterministic merge primitive `merge_index_payloads` in `src/seedpass/core/sync_conflict.py`.
- Conflict resolver now uses order-independent comparison:
  1) higher `modified_ts`
  2) on tie, lexicographically larger canonical entry hash.
- Integrated merge primitive into Nostr merge path (`EncryptionManager.decrypt_and_save_index_from_nostr(..., merge=True)`).
- Added encrypted sync metadata `_sync_meta` into index payload to track merge strategy and source tags.

## Patterns / reusable knowledge
- Keep merge logic centralized and deterministic to avoid divergent state from different delta arrival orders.
- Use payload-derived source tags + bounded source history in encrypted index metadata for debugging merge provenance without plaintext side channels.

## Warnings / gotchas
- Existing tests that implicitly relied on "incoming wins on equal timestamp" need explicit timestamp separation if validating LWW semantics.
- Extended Item 12 conflict-safe sync with deterministic field-level merge rules for equal-timestamp conflicts in `sync_conflict.merge_index_payloads`.
- Equal-ts conflicts now perform deterministic winner selection by hash plus selective field union (`username/url/notes/...`) and conservative archive OR behavior.
- Added order-independence regression tests covering both whole-entry tie resolution and field-level union behavior.
- Integrated resolver in `EncryptionManager.decrypt_and_save_index_from_nostr(..., merge=True)` with source-tagged encrypted sync metadata.
## 2026-03-01 - Sync conflict v2 tombstones
- Added deterministic sync strategy `modified_ts_hash_tombstone_v2` in `src/seedpass/core/sync_conflict.py`.
- Added `_sync_meta.tombstones` merge semantics with timestamp-first then event-hash tie-break, and retention cap.
- Added kind-aware equal-timestamp unions (including deterministic `tags`/`custom_fields` union).
- `EntryManager.delete_entry` now emits local tombstones before removing entries so deletions can propagate across merge-based sync.
- Regression coverage added in `src/tests/test_delta_merge.py` for order-independence, kind-aware unions, and tombstone convergence.
- Validation run: `src/tests/test_delta_merge.py` (7 passed), plus `src/tests/test_profile_management.py src/tests/test_api.py src/tests/test_api_new_endpoints.py` (83 passed).
## 2026-03-01 - CLI discoverability refresh for agents/users
- Updated root CLI help in `src/seedpass/cli/__init__.py` to direct users/agents to `seedpass capabilities` and subgroup `--help`.
- Updated vault unlock success tip in `src/seedpass/cli/vault.py` to explicitly mention `seedpass capabilities` after unlock/login.
- Expanded `src/seedpass/cli/capabilities.py` map with:
  - `security_features.sync` (deterministic conflict strategy `modified_ts_hash_tombstone_v2` + tombstones metadata)
  - `export_controls` commands and defaults
  - `posture` command/check descriptions
  - richer approval coverage and help hints (including post-login guidance)
- Updated agent discoverability surfaces in `src/seedpass/cli/agent.py`:
  - richer group help text
  - `agent init` now returns `next_steps` including capabilities/bootstrap discovery
  - `agent bootstrap-context` now advertises export/posture command groups
- Validation: `src/tests/test_typer_cli.py` + `src/tests/test_cli_agent_mode.py` passed (`92 passed`).
## 2026-03-01 - Sync replay/idempotency hardening
- Hardened `src/seedpass/core/sync_conflict.py` to remove wall-clock dependence from merge metadata:
  - `last_merge_ts` now derived deterministically from existing/incoming metadata and max observed entry/tombstone timestamps.
  - deleted-entry fallback tombstone timestamp now derived from merge state, not `time.time()`.
- Added integer normalization helper for metadata parsing (`_safe_int`) and centralized max timestamp helpers.
- Added replay-focused tests in `src/tests/test_delta_merge.py`:
  - idempotent replay of same payload (`once == twice`)
  - stale payload cannot override newer state
  - stale re-add cannot resurrect tombstoned entry
  - newer recreate supersedes tombstone and clears it
- Validation: `src/tests/test_delta_merge.py` (11 passed) + broader regression set (`test_profile_management.py`, `test_api.py`, `test_api_new_endpoints.py`) (83 passed).
- Added vault-boundary idempotency regression in `src/tests/test_delta_merge.py::test_merge_replay_idempotent_through_vault_boundary` by replaying same merged encrypted payload twice after baseline sync.
## 2026-03-01 - Item 12 docs/contract pass
- Added `docs/sync_conflict_contract.md` documenting deterministic merge strategy `modified_ts_hash_tombstone_v2`, `_sync_meta` schema, tombstone semantics, replay guarantees, and retention behavior.
- Linked contract doc from `docs/SPEC.md`, `docs/nostr_setup.md`, and `docs/README.md`.
- Added `test_merge_last_merge_ts_order_independent` in `src/tests/test_delta_merge.py` to lock deterministic metadata ordering behavior.
- Validation: `src/tests/test_delta_merge.py` (13 passed) and targeted CLI discoverability checks (2 passed).
## 2026-03-01 - Item 13 policy-as-code workflow primitives
- Extended agent policy CLI in `src/seedpass/cli/agent.py`:
  - `agent policy-lint --file <path> [--format json|text]` with deterministic `policy_stamp` and full `policy_hash`.
  - `agent policy-review --file <path>` with deterministic unified diff, structured `diff_summary`, and risky finding surfacing.
  - `agent policy-apply --file <path>` with `--dry-run` and risk gate (`--allow-risky`) plus audit event `agent_policy_applied`.
- Added helper functions for file-based policy normalization, full-hash computation, and rule-level change summary.
- Updated discovery surfaces:
  - capabilities policy commands now include review/apply and policy-as-code support flags.
  - bootstrap context now includes `agent policy-review` and `agent policy-apply`.
- Added tests:
  - `test_agent_policy_lint_file`
  - `test_agent_policy_review_and_apply_risk_gate`
  - bootstrap context expectations for new policy commands
  - capabilities JSON assertion for policy change-review support.
- Added docs: `docs/policy_as_code.md` and linked from `docs/README.md`.
- Validation: `src/tests/test_cli_agent_mode.py` + `src/tests/test_typer_cli.py` passed (94 passed).
## 2026-03-01 - Item 14 deterministic export controls hardening
- Hardened `src/seedpass/core/agent_export_policy.py` policy-filtered manifest verification:
  - manifest version advanced to v2 (with backward-compat support for v1)
  - deterministic index sorting helper for mixed/non-numeric indexes
  - added `entries_sha256` integrity field (canonical hash of filtered entries)
  - added checks for included count, schema version consistency, redacted fields consistency, entry-kind allowlist conformance, and redaction sentinel conformance
  - robust integer parsing to avoid verifier crashes on malformed manifests
- Added tamper-detection tests:
  - CLI: `test_agent_export_manifest_verify_detects_tampered_entries`
  - API: `test_export_manifest_verify_endpoint_detects_tamper`
- Updated capabilities map to surface manifest entry hash verification support.
- Updated docs (`docs/policy_as_code.md`) to document deterministic manifest integrity fields and tamper verification.
- Validation: `src/tests/test_cli_agent_mode.py src/tests/test_typer_cli.py src/tests/test_api_new_endpoints.py` => 152 passed.
## 2026-03-01 - Item 15 posture tooling expansion
- Expanded `agent posture-check` findings in `src/seedpass/cli/agent.py` with additional controls:
  - `approvals_missing_required_actions` (export/reveal_parent_seed/private_key_retrieval gate completeness)
  - `high_risk_unlock_ttl_too_long` (>1800s)
  - `over_permissive_read_rule` (broad secret-read allow rule detection)
  - `private_read_without_approval_gate` (private-kind reads without private key approval gate)
  - `identity_rotation_window_too_long` (rotation_days > 90)
  - `token_rotation_overdue` (active token age exceeds bound identity rotation_days)
- Updated capabilities posture checklist in `src/seedpass/cli/capabilities.py` to reflect new checks.
- Added posture regression tests in `src/tests/test_cli_agent_mode.py`:
  - `test_agent_posture_check_flags_policy_gate_and_rule_issues`
  - `test_agent_posture_check_flags_token_rotation_overdue`
- Validation: `src/tests/test_cli_agent_mode.py src/tests/test_typer_cli.py` (97 passed) and `src/tests/test_api_new_endpoints.py` (57 passed).
## 2026-03-01 - Item 15 runtime config posture checks
- Extended `agent posture-check` in `src/seedpass/cli/agent.py` with opt-in runtime config audit:
  - new flag `--check-runtime-config` with broker options (`--auth-broker`, `--password-env`, `--broker-service`, `--broker-account`, `--broker-command`)
  - requires `--fingerprint` when runtime check is requested
  - runtime summary fields: `runtime_config_status`, `runtime_config_error`, `runtime_finding_count`
- Added runtime findings:
  - `quick_unlock_enabled`
  - `weak_kdf_iterations`
  - `high_risk_partition_persistently_unlocked`
- Added additional posture checks in this pass:
  - `approvals_missing_required_actions`
  - `high_risk_unlock_ttl_too_long`
  - `over_permissive_read_rule`
  - `private_read_without_approval_gate`
  - `identity_rotation_window_too_long`
  - `token_rotation_overdue`
- Updated capabilities posture check list to include runtime config drift checks.
- Added/updated tests in `src/tests/test_cli_agent_mode.py` for new posture findings and runtime-check behavior.
- Validation: `src/tests/test_cli_agent_mode.py src/tests/test_typer_cli.py src/tests/test_api_new_endpoints.py` => 156 passed.
## 2026-03-01 - Item 15 remediation bundle command
- Added `agent posture-remediate` in `src/seedpass/cli/agent.py` to convert current posture findings into deterministic actionable remediation steps.
- Command supports `--check-runtime-config` with broker auth options and mirrors runtime drift checks used by posture-check.
- Added remediation mapping for key findings (policy gates, export controls, safe output, isolation, token hygiene, rotation, runtime config drift).
- Updated discovery:
  - bootstrap context posture commands now include `agent posture-remediate`
  - capabilities posture command list includes remediation command
  - text capabilities summary mentions remediation bundles
- Added tests:
  - `test_agent_posture_remediate_emits_actions`
  - `test_agent_posture_remediate_runtime_requires_fingerprint`
  - bootstrap context posture command assertion
  - capabilities JSON posture command assertion
- Validation: `src/tests/test_cli_agent_mode.py src/tests/test_typer_cli.py src/tests/test_api_new_endpoints.py` => 158 passed.
## 2026-03-01 - Docs and landing updates for agent/user discoverability
- Updated root `README.md` with a dedicated **Agent and Automation Security Features** section covering implemented controls and command references (`capabilities`, policy, tokens, leases, approvals, isolation, automation jobs, recovery, export controls, posture tooling, audit logging).
- Updated `docs/README.md` to include agent/autonomy docs and explicit discoverability commands (`seedpass --help`, group help, `capabilities`, `agent bootstrap-context`).
- Expanded `docs/security.md` with current agent security controls and links to core plan/contract docs.
- Updated `docs/security_readiness_checklist.md` with a new **Agent Autonomy Control Track (15-item plan)** status table and evidence pointers.
- Updated `docs/agent_autonomy_security_plan.md` with a dated implementation snapshot (implemented vs in-progress).
- Updated website docs index in `landing/docs.html` to include `security_readiness_checklist.md`, `agent_autonomy_security_plan.md`, `policy_as_code.md`, and `sync_conflict_contract.md`.
- Added a new **For Agents** section to `landing/index.html` (with nav anchor) and supporting styles in `landing/style.css`, including quickstart command and agent-specific feature cards.
