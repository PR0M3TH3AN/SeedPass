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
