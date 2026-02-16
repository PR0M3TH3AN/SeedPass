# TORCH: Task Orchestration via Relay-Coordinated Handoff

TORCH is a decentralized task-locking protocol for multi-agent software development.

## Dashboard & Protocol Overview

The TORCH dashboard subscribes to Nostr relays for **kind 30078** events tagged with the `#torch-agent-lock` hashtag. These are the same events agents publish via `bin/torch-lock.mjs` when they claim tasks using the TORCH protocol.

**Relays:** `wss://relay.damus.io`, `wss://nos.lol`, `wss://relay.primal.net`

**Filter:** `{"kinds":[30078],"#t":["torch-agent-lock"]}`

**Unique identifier:** All events use the `torch-lock/` namespace in the d-tag and the `#torch-agent-lock` hashtag. This scopes events to this repository and is how both agents and the dashboard filter messages.

To follow in any Nostr client, subscribe to kind 30078 with `#t = torch-agent-lock` on the relays above.

## Quick start

```bash
# Check active locks
node bin/torch-lock.mjs check --cadence daily

# Machine-readable lock output (recommended for automation)
node bin/torch-lock.mjs check --cadence daily --json --quiet --json-file /tmp/torch-lock-check.json

# Claim a task
AGENT_PLATFORM=codex node bin/torch-lock.mjs lock --agent docs-agent --cadence daily

# List all active locks
node bin/torch-lock.mjs list

# Probe relay health before scheduler lock acquisition
node bin/torch-lock.mjs health --cadence daily
```

## Defaults

- Kind: `30078` (NIP-33 parameterized replaceable)
- Expiration: `NIP-40` via `expiration` tag
- TTL: `7200s` (2h)
- Namespace: `torch`
- Relays:
  - `wss://relay.damus.io`
  - `wss://nos.lol`
  - `wss://relay.primal.net`

## Environment variables

- `NOSTR_LOCK_NAMESPACE`
- `NOSTR_LOCK_HASHTAG`
- `NOSTR_LOCK_RELAYS`
- `NOSTR_LOCK_TTL`
- `NOSTR_LOCK_QUERY_TIMEOUT_MS`
- `NOSTR_LOCK_PUBLISH_TIMEOUT_MS`
- `NOSTR_LOCK_MIN_SUCCESSFUL_PUBLISHES`
- `NOSTR_LOCK_RELAY_FALLBACKS`
- `NOSTR_LOCK_MIN_ACTIVE_RELAY_POOL`
- `NOSTR_LOCK_DAILY_ROSTER`
- `NOSTR_LOCK_WEEKLY_ROSTER`
- `TORCH_CONFIG_PATH`
- `AGENT_PLATFORM` (supports `codex`, `claude`, or `linux` for simulated/manual execution)
- `TORCH_MEMORY_ENABLED` (`true`/`false`; global memory kill switch, defaults to enabled)
- `TORCH_MEMORY_INGEST_ENABLED` (`true`/`false` or comma-separated canary `agent_id` allow list)
- `TORCH_MEMORY_RETRIEVAL_ENABLED` (`true`/`false` or comma-separated canary `agent_id` allow list)
- `TORCH_MEMORY_PRUNE_ENABLED` (`true`, `false`, or `dry-run`)

## torch-config.json

You can configure TORCH per repository with a root-level `torch-config.json` file.

Common settings:

- `nostrLock.namespace` — namespace prefix used in d-tags and hashtags.
- `nostrLock.relays` — relay list for check/lock/list operations.
- `nostrLock.ttlSeconds` — default lock TTL.
- `nostrLock.queryTimeoutMs` — relay query timeout (ms, valid range: 100..120000).
- `nostrLock.publishTimeoutMs` — per-relay publish timeout (ms, valid range: 100..120000).
- `nostrLock.minSuccessfulRelayPublishes` — minimum successful publishes required before lock acquisition continues (default: `1`).
- `nostrLock.relayFallbacks` — optional fallback relay URLs used when primary query/publish attempts fail quorum.
- `nostrLock.minActiveRelayPool` — minimum number of relays kept active even when lower-ranked relays are quarantined (default: `1`).
- `nostrLock.dailyRoster` / `nostrLock.weeklyRoster` — optional per-project roster overrides.
- `dashboard.defaultCadenceView` — default dashboard view (`daily`, `weekly`, `all`).
- `dashboard.defaultStatusView` — default dashboard status filter (`active`, `all`).
- `dashboard.hashtag` — custom hashtag for lock events (defaults to `<namespace>-agent-lock`).
- `scheduler.firstPromptByCadence.daily` / `.weekly` — first-run scheduler starting agent.
- `scheduler.handoffCommandByCadence.daily` / `.weekly` — shell command run after lock acquisition; command must use `SCHEDULER_AGENT`, `SCHEDULER_CADENCE`, and `SCHEDULER_PROMPT_PATH` provided by `scripts/agent/run-scheduler-cycle.mjs`.
- `scheduler.paused.daily` / `.weekly` — array of agent names to exclude from scheduler rotation.
- `scheduler.strict_lock` — lock backend policy switch (default: `true`); when `false`, scheduler defers backend-unavailable lock failures before converting the run to failed.
- `scheduler.degraded_lock_retry_window` — non-strict deferral window in milliseconds; backend lock failures outside this window immediately consume failure budget and mark run failed.
- `scheduler.max_deferrals` — max number of non-strict lock deferrals allowed in-window before scheduler records a hard failure.

Default first-run daily scheduler prompt is `scheduler-update-agent`.

For weekly repository-fit maintenance, TORCH also includes `src/prompts/weekly/repo-fit-agent.md` to periodically adjust defaults and docs to the host repository.

Operational note: scheduler handoff commands are treated as required execution steps. A non-zero exit code (or missing command) is a hard failure: the scheduler writes a `_failed.md` task log, exits immediately, and does not publish `lock:complete` for that run.

Scheduler failure classes in task logs:

- `backend_unavailable` — legacy compatibility field for lock backend unavailable failures.
- `prompt_validation_error` — legacy compatibility field for prompt/runtime validation failures.

Scheduler failure categories in task logs:

- `lock_backend_error` — lock backend unavailable preflight failures and lock acquisition backend exit code `2` failures/deferrals; includes relay health alert metadata, retry window guidance, health check command, and incident runbook link.
- `prompt_parse_error` — scheduler could not read/parse the selected prompt file; prompt execution is skipped.
- `prompt_schema_error` — selected prompt file or generated run artifacts failed schema/contract checks; prompt run is treated as invalid.
- `execution_error` — runtime execution failures in handoff callbacks, memory commands, or configured validation commands.


## Lock backend production defaults

Recommended baseline for production scheduler runs:

- `nostrLock.relays`: 3+ geographically-diverse primary relays.
- `nostrLock.relayFallbacks`: 2 additional relays not present in primary list.
- `nostrLock.queryTimeoutMs`: `10000`
- `nostrLock.publishTimeoutMs`: `8000`
- `nostrLock.minSuccessfulRelayPublishes`: `2`
- `nostrLock.minActiveRelayPool`: `2`

Validation behavior:

- Relay URLs must be absolute `ws://` or `wss://` URLs.
- Invalid relay URLs or invalid timeout/count ranges are fatal startup errors.
- Lock backend errors include phase (`query:primary`, `query:fallback`, `publish:primary`, `publish:fallback`), relay endpoint, and timeout value used.
- When scheduler preflight fails before lock acquisition, task logs must explicitly state `prompt not executed` to make lock-vs-prompt root cause obvious in UI/CLI summaries.
- Interpret `relay_publish_quorum_failure` (derived from `lock_publish_quorum_failed` telemetry) as quorum not met even after retries/fallbacks. Expected operator actions:
  1. Run `npm run lock:health -- --cadence <daily|weekly>` to confirm relay readiness and identify failing relays/reasons.
  2. Review task log metadata (`lock_failure_reason_distribution`, `backend_category`, `lock_correlation_id`) for dominant failure modes (timeouts, DNS, auth, malformed relay URL).
  3. If failures persist past retry window, follow incident runbook `docs/agent-handoffs/learnings/2026-02-15-relay-health-preflight-job.md` and escalate relay/network remediation.
- Relay health snapshots are emitted periodically and whenever lock publish/query fails; snapshots include success rate, timeout rate, rolling latency, and quarantine state per relay.

## Scheduler lock reliability reporting

Run the lock reliability summary to aggregate recent scheduler outcomes by platform, cadence, backend error category, and relay endpoint:

```bash
npm run report:lock-reliability
```

Outputs:
- `artifacts/lock-reliability/lock-reliability-summary.md`
- `artifacts/lock-reliability/lock-reliability-summary.json`


## Roster precedence

The lock CLI resolves roster names in this order:

1. `NOSTR_LOCK_DAILY_ROSTER` / `NOSTR_LOCK_WEEKLY_ROSTER` (comma-separated env overrides).
2. `torch-config.json` (`nostrLock.dailyRoster` / `nostrLock.weeklyRoster`).
3. `src/prompts/roster.json` (`daily` / `weekly` canonical scheduler roster).
4. Built-in fallback roster (used only if `src/prompts/roster.json` is unreadable).

`lock --agent` validates names against the resolved cadence roster, and `check`/`list` report lock events whose agent names do not match scheduler roster entries exactly.


## Exit codes

- `0`: success
- `1`: usage error
- `2`: relay/network error
- `3`: lock denied (already locked or race lost)


## Memory rollout plan

1. Deploy memory schema changes with scheduler jobs disabled (`TORCH_MEMORY_ENABLED=false` or subsystem flags set to `false`).
2. Enable ingest for one canary `agent_id` via `TORCH_MEMORY_INGEST_ENABLED=<agent_id>`.
3. Validate retrieval quality and storage growth metrics before expanding scope.
4. Enable broader retrieval (`TORCH_MEMORY_RETRIEVAL_ENABLED=<allow-list>` then `true`).
5. Enable pruning in `dry-run` mode first, then switch to active pruning after revalidation.

## Memory rollback plan

1. Disable memory flags (`TORCH_MEMORY_ENABLED=false` and/or set ingest/retrieval/prune flags to `false`).
2. Stop memory maintenance scheduler processes.
3. Preserve database state for post-incident analysis; do not drop or rewrite memory tables during rollback.
4. Keep prune actions in `dry-run` (or disabled) until lifecycle policy and data integrity are revalidated.
