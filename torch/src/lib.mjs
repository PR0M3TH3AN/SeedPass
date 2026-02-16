#!/usr/bin/env node

// TORCH — Task Orchestration via Relay-Coordinated Handoff
// Generic Nostr-based task locking for multi-agent development.

import { generateSecretKey as _generateSecretKey, getPublicKey as _getPublicKey, finalizeEvent as _finalizeEvent } from 'nostr-tools/pure';
import { useWebSocketImplementation } from 'nostr-tools/relay';
import WebSocket from 'ws';
import {
  loadTorchConfig as _loadTorchConfig,
  getRelays as _getRelays,
  getNamespace as _getNamespace,
  getTtl as _getTtl,
  getHashtag as _getHashtag,
} from './torch-config.mjs';
import {
  DEFAULT_DASHBOARD_PORT,
  VALID_CADENCES,
  KIND_APP_DATA,
  RACE_CHECK_DELAY_MS,
} from './constants.mjs';
import { cmdInit, cmdUpdate } from './ops.mjs';
import { parseArgs } from './cli-parser.mjs';
import { getRoster as _getRoster } from './roster.mjs';
import { queryLocks as _queryLocks, publishLock as _publishLock, parseLockEvent } from './lock-ops.mjs';
import { cmdDashboard } from './dashboard.mjs';
import {
  inspectMemory,
  listMemories,
  memoryStats,
  pinMemory,
  triggerPruneDryRun,
  unpinMemory,
} from './services/memory/index.js';
import { ExitError } from './errors.mjs';
import { todayDateStr, nowUnix, detectPlatform } from './utils.mjs';
import { runRelayHealthCheck } from './relay-health.mjs';
import fs from 'node:fs/promises';
import path from 'node:path';
import { getCompletedAgents } from './lock-utils.mjs';

useWebSocketImplementation(WebSocket);

// Re-export for backward compatibility/library usage
export { parseLockEvent, cmdDashboard, _queryLocks as queryLocks, _publishLock as publishLock };

/**
 * Checks the status of the repository locks for a given cadence.
 *
 * It aggregates data from three sources:
 * 1. Configuration (paused agents)
 * 2. Local logs (completed agents)
 * 3. Nostr relays (current active locks)
 *
 * It outputs a JSON object describing the state (locked, available, excluded agents).
 *
 * @param {string} cadence - 'daily' or 'weekly'
 * @param {Object} [deps] - Dependency injection
 * @returns {Promise<Object>} - The check result object
 */
export async function cmdCheck(cadence, deps = {}) {
  const {
    getRelays = _getRelays,
    getNamespace = _getNamespace,
    loadTorchConfig = _loadTorchConfig,
    queryLocks = _queryLocks,
    getRoster = _getRoster,
    getDateStr = todayDateStr,
    log = console.log,
    error = console.error,
    logDir = 'task-logs',
    ignoreLogs = false,
    json = false,
    jsonFile = null,
    quiet = false,
  } = deps;

  const relays = getRelays();
  const namespace = getNamespace();
  const dateStr = getDateStr();
  const config = loadTorchConfig();
  const pausedAgents = config.scheduler.paused[cadence] || [];

  if (!quiet) {
    error(`Checking locks: namespace=${namespace}, cadence=${cadence}, date=${dateStr}`);
    error(`Relays: ${relays.join(', ')}`);
    if (pausedAgents.length > 0) {
      error(`Paused agents: ${pausedAgents.join(', ')}`);
    }
  }

  let completedAgents = new Set();
  if (!ignoreLogs) {
    completedAgents = await getCompletedAgents(cadence, logDir, deps);
    if (!quiet && completedAgents.size > 0) {
      error(`Completed agents (logs): ${[...completedAgents].join(', ')}`);
    }
  }

  const locks = await queryLocks(relays, cadence, dateStr, namespace);
  const lockedAgents = [...new Set(locks.map((l) => l.agent).filter(Boolean))];
  const roster = getRoster(cadence);
  const rosterSet = new Set(roster);

  const excludedAgentsSet = new Set([...lockedAgents, ...pausedAgents, ...completedAgents]);
  const excludedAgents = [...excludedAgentsSet];
  const unknownLockedAgents = lockedAgents.filter((agent) => !rosterSet.has(agent));
  const available = roster.filter((a) => !excludedAgentsSet.has(a));

  const result = {
    namespace,
    cadence,
    date: dateStr,
    locked: lockedAgents.sort(),
    paused: pausedAgents.sort(),
    completed: [...completedAgents].sort(),
    excluded: excludedAgents.sort(),
    available: available.sort(),
    lockCount: locks.length,
    unknownLockedAgents: unknownLockedAgents.sort(),
    locks: locks.map((l) => ({
      agent: l.agent,
      eventId: l.eventId,
      createdAt: l.createdAtIso,
      expiresAt: l.expiresAtIso,
      platform: l.platform,
    })),
  };

  const output = json ? JSON.stringify(result) : JSON.stringify(result, null, 2);

  if (jsonFile) {
    const resolvedPath = path.resolve(process.cwd(), jsonFile);
    await fs.mkdir(path.dirname(resolvedPath), { recursive: true });
    await fs.writeFile(resolvedPath, `${output}\n`, 'utf8');
  }

  if (json || !quiet) {
    log(output);
  }

  return result;
}

/**
 * Attempts to acquire an exclusive lock for an agent on the specified cadence.
 *
 * Algorithm:
 * 1. Validate agent against the roster.
 * 2. Query relays for existing valid locks (checking for conflicts).
 * 3. Generate a new ephemeral keypair and build a lock event (kind 30078).
 * 4. Publish the lock event to relays.
 * 5. Wait for propagation (raceCheckDelayMs) and re-query to confirm no earlier lock won the race.
 *
 * @param {string} agent - Agent name
 * @param {string} cadence - 'daily' or 'weekly'
 * @param {boolean} [dryRun=false] - If true, skips publishing
 * @param {Object} [deps] - Dependency injection
 * @returns {Promise<{status: string, eventId: string}>}
 * @throws {ExitError} If lock is denied (already locked, completed, or race lost)
 */
export async function cmdLock(agent, cadence, optionsOrDryRun = false, deps = {}) {
  const options = typeof optionsOrDryRun === 'object' ? optionsOrDryRun : { dryRun: !!optionsOrDryRun };
  const { dryRun = false, platform = null, model = null } = options;

  const {
    getRelays = _getRelays,
    getNamespace = _getNamespace,
    getHashtag = _getHashtag,
    getTtl = _getTtl,
    queryLocks = _queryLocks,
    getRoster = _getRoster,
    publishLock = _publishLock,
    generateSecretKey = _generateSecretKey,
    getPublicKey = _getPublicKey,
    finalizeEvent = _finalizeEvent,
    raceCheckDelayMs = RACE_CHECK_DELAY_MS,
    getDateStr = todayDateStr,
    log = console.log,
    error = console.error
  } = deps;

  const relays = getRelays();
  const namespace = getNamespace();
  const hashtag = getHashtag();
  const dateStr = getDateStr();
  const ttl = getTtl();
  const now = nowUnix();
  const expiresAt = now + ttl;

  error(`Locking: namespace=${namespace}, agent=${agent}, cadence=${cadence}, date=${dateStr}`);
  error(`Hashtag: #${hashtag}`);
  error(`TTL: ${ttl}s, expires: ${new Date(expiresAt * 1000).toISOString()}`);
  error(`Relays: ${relays.join(', ')}`);

  const roster = getRoster(cadence);
  if (!roster.includes(agent)) {
    error(`ERROR: agent "${agent}" is not in the ${cadence} roster`);
    error(`Allowed ${cadence} agents: ${roster.join(', ')}`);
    throw new ExitError(1, 'Agent not in roster');
  }

  error('Step 1: Checking for existing locks...');
  const existingLocks = await queryLocks(relays, cadence, dateStr, namespace);
  const conflicting = existingLocks.filter((l) => l.agent === agent);

  if (conflicting.length > 0) {
    const earliest = conflicting.sort((a, b) => a.createdAt - b.createdAt)[0];

    // Check if it is a completed task
    if (earliest.status === 'completed') {
       error(`LOCK DENIED: Task already completed by event ${earliest.eventId}`);
       log('LOCK_STATUS=denied');
       log('LOCK_REASON=already_completed');
       throw new ExitError(3, 'Task already completed');
    }

    error(
      `LOCK DENIED: ${agent} already locked by event ${earliest.eventId} ` +
        `(created ${earliest.createdAtIso}, platform: ${earliest.platform})`,
    );
    log('LOCK_STATUS=denied');
    log('LOCK_REASON=already_locked');
    log(`LOCK_EXISTING_EVENT=${earliest.eventId}`);
    throw new ExitError(3, 'Lock denied');
  }

  error('Step 2: Generating ephemeral keypair...');
  const sk = generateSecretKey();
  const pk = getPublicKey(sk);
  error(`  Ephemeral pubkey: ${pk.slice(0, 16)}...`);

  error('Step 3: Building lock event...');
  const event = finalizeEvent(
    {
      kind: KIND_APP_DATA,
      created_at: now,
      tags: [
        ['d', `${namespace}-lock/${cadence}/${agent}/${dateStr}`],
        ['t', hashtag],
        ['t', `${namespace}-lock-${cadence}`],
        ['t', `${namespace}-lock-${cadence}-${dateStr}`],
        ['expiration', String(expiresAt)],
      ],
      content: JSON.stringify({
        agent,
        cadence,
        status: 'started',
        namespace,
        date: dateStr,
        platform: platform || process.env.AGENT_PLATFORM || detectPlatform() || 'unknown',
        model: model || process.env.AGENT_MODEL || 'unknown',
        lockedAt: new Date(now * 1000).toISOString(),
        expiresAt: new Date(expiresAt * 1000).toISOString(),
      }),
    },
    sk,
  );

  error(`  Event ID: ${event.id}`);

  if (dryRun) {
    error('Step 4: [DRY RUN] Skipping publish — event built but not sent');
    error('RACE CHECK: won (dry run — no real contention possible)');
  } else {
    error('Step 4: Publishing to relays...');
    await publishLock(relays, event);

    error('Step 5: Race check...');
    await new Promise((resolve) => setTimeout(resolve, raceCheckDelayMs));

    const postLocks = await queryLocks(relays, cadence, dateStr, namespace);
    const racingLocks = postLocks
      .filter((l) => l.agent === agent)
      .sort((a, b) => (a.createdAt - b.createdAt) || String(a.eventId).localeCompare(String(b.eventId)));

    if (racingLocks.length > 1 && racingLocks[0].eventId !== event.id) {
      const winner = racingLocks[0];
      error(
        `RACE CHECK: lost (earlier lock by event ${winner.eventId}, created ${winner.createdAtIso})`,
      );
      log('LOCK_STATUS=race_lost');
      log('LOCK_REASON=earlier_claim_exists');
      log(`LOCK_WINNER_EVENT=${winner.eventId}`);
      throw new ExitError(3, 'Race check lost');
    }

    error('RACE CHECK: won');
  }

  log('LOCK_STATUS=ok');
  log(`LOCK_EVENT_ID=${event.id}`);
  log(`LOCK_PUBKEY=${pk}`);
  log(`LOCK_AGENT=${agent}`);
  log(`LOCK_HASHTAG=${hashtag}`);
  log(`LOCK_CADENCE=${cadence}`);
  log(`LOCK_DATE=${dateStr}`);
  log(`LOCK_EXPIRES=${expiresAt}`);
  log(`LOCK_EXPIRES_ISO=${new Date(expiresAt * 1000).toISOString()}`);
  return { status: 'ok', eventId: event.id };
}

/**
 * Lists all active locks for the specified cadence (or all cadences if null).
 * It prints a formatted table to stdout with lock age, TTL, and event ID.
 *
 * @param {string|null} cadence - Filter by cadence ('daily', 'weekly') or null for all
 * @param {Object} [deps] - Dependency injection
 * @returns {Promise<void>}
 */
export async function cmdList(cadence, deps = {}) {
  const {
    getRelays = _getRelays,
    getNamespace = _getNamespace,
    queryLocks = _queryLocks,
    getRoster = _getRoster,
    getDateStr = todayDateStr,
    log = console.log,
    error = console.error
  } = deps;

  const relays = getRelays();
  const namespace = getNamespace();
  const dateStr = getDateStr();
  const cadences = cadence ? [cadence] : [...VALID_CADENCES];

  error(`Listing active locks: namespace=${namespace}, cadences=${cadences.join(', ')}`);

  const results = await Promise.all(
    cadences.map(async (c) => {
      const locks = await queryLocks(relays, c, dateStr, namespace);
      return { c, locks };
    }),
  );

  for (const { c, locks } of results) {
    log(`\n${'='.repeat(72)}`);
    log(`Active ${namespace} ${c} locks (${dateStr})`);
    log('='.repeat(72));

    if (locks.length === 0) {
      log('  (no active locks)');
      continue;
    }

    const sorted = locks.sort((a, b) => a.createdAt - b.createdAt);
    for (const lock of sorted) {
      const age = nowUnix() - lock.createdAt;
      const ageMin = Math.round(age / 60);

      let remainMin = '?';
      if (lock.status === 'completed') {
          remainMin = 'done';
      } else if (lock.expiresAt) {
          const remaining = lock.expiresAt - nowUnix();
          remainMin = Math.round(remaining / 60);
      }

      log(
        `  ${(lock.agent ?? 'unknown').padEnd(30)} ` +
          `age: ${String(ageMin).padStart(4)}m  ` +
          `ttl: ${String(remainMin).padStart(4)}  ` +
          `platform: ${lock.platform ?? '?'}  ` +
          `event: ${lock.eventId?.slice(0, 12)}...`,
      );
    }

    const roster = getRoster(c);
    const rosterSet = new Set(roster);
    const lockedAgents = new Set(locks.map((l) => l.agent).filter(Boolean));
    const unknownLockedAgents = [...lockedAgents].filter((agent) => !rosterSet.has(agent));
    const available = roster.filter((a) => !lockedAgents.has(a));

    if (unknownLockedAgents.length > 0) {
      log(`  Warning: lock events found with non-roster agent names: ${unknownLockedAgents.join(', ')}`);
    }

    log(`\n  Locked: ${lockedAgents.size}/${roster.length}`);
    log(`  Available: ${available.join(', ') || '(none)'}`);
  }
}

/**
 * Marks a task as permanently completed by publishing a new lock event with
 * `status: 'completed'` and no expiration.
 *
 * This function:
 * 1. Verifies that the agent currently holds a valid lock.
 * 2. Publishes a replacement event that preserves the original `startedAt` time.
 *
 * @param {string} agent - Agent name
 * @param {string} cadence - 'daily' or 'weekly'
 * @param {boolean} [dryRun=false] - If true, skips publishing
 * @param {Object} [deps] - Dependency injection
 * @returns {Promise<{status: string, eventId: string}>}
 * @throws {ExitError} If no active lock exists for the agent
 */
export async function cmdComplete(agent, cadence, optionsOrDryRun = false, deps = {}) {
  const options = typeof optionsOrDryRun === 'object' ? optionsOrDryRun : { dryRun: !!optionsOrDryRun };
  const { dryRun = false, platform = null, model = null } = options;

  const {
    getRelays = _getRelays,
    getNamespace = _getNamespace,
    getHashtag = _getHashtag,
    queryLocks = _queryLocks,
    publishLock = _publishLock,
    generateSecretKey = _generateSecretKey,
    getPublicKey = _getPublicKey,
    finalizeEvent = _finalizeEvent,
    getDateStr = todayDateStr,
    log = console.log,
    error = console.error
  } = deps;

  const relays = getRelays();
  const namespace = getNamespace();
  const hashtag = getHashtag();
  const dateStr = getDateStr();
  const now = nowUnix();

  error(`Completing task: namespace=${namespace}, agent=${agent}, cadence=${cadence}, date=${dateStr}`);
  error(`Relays: ${relays.join(', ')}`);

  // 1. Find existing lock
  const locks = await queryLocks(relays, cadence, dateStr, namespace);
  const myLock = locks.find((l) => l.agent === agent);

  if (!myLock) {
    error(`ERROR: No active lock found for agent "${agent}" on ${dateStr}.`);
    error(`Cannot complete a task that is not locked or has already expired.`);
    throw new ExitError(1, 'No active lock found');
  }

  if (myLock.status === 'completed') {
    error(`Task is already marked as completed (event ${myLock.eventId}).`);
    log('LOCK_STATUS=completed');
    return { status: 'completed', eventId: myLock.eventId };
  }

  // 2. Build completion event
  const startedAtIso = myLock.createdAtIso;

  error('Step 1: Generating completion event...');
  const sk = generateSecretKey();
  const pk = getPublicKey(sk);

  const event = finalizeEvent(
    {
      kind: KIND_APP_DATA,
      created_at: now,
      tags: [
        ['d', `${namespace}-lock/${cadence}/${agent}/${dateStr}`],
        ['t', hashtag],
        ['t', `${namespace}-lock-${cadence}`],
        ['t', `${namespace}-lock-${cadence}-${dateStr}`],
        // No expiration tag -> permanent
      ],
      content: JSON.stringify({
        agent,
        cadence,
        status: 'completed',
        namespace,
        date: dateStr,
        platform: platform || process.env.AGENT_PLATFORM || detectPlatform() || 'unknown',
        model: model || process.env.AGENT_MODEL || 'unknown',
        startedAt: startedAtIso,
        completedAt: new Date(now * 1000).toISOString(),
      }),
    },
    sk,
  );

  error(`  Event ID: ${event.id}`);

  if (dryRun) {
    error('Step 2: [DRY RUN] Skipping publish — event built but not sent');
  } else {
    error('Step 2: Publishing completion event...');
    await publishLock(relays, event);
    error('  Published successfully.');
  }

  log('LOCK_STATUS=completed');
  log(`LOCK_EVENT_ID=${event.id}`);
  log(`LOCK_PUBKEY=${pk}`);
  log(`LOCK_AGENT=${agent}`);
  log(`LOCK_CADENCE=${cadence}`);
  log(`LOCK_DATE=${dateStr}`);

  return { status: 'completed', eventId: event.id };
}

function usage() {
  console.error(`Usage: torch-lock <command> [options]

Commands:
  check     --cadence <daily|weekly>               Check locked agents (JSON)
  lock      --agent <name> --cadence <daily|weekly> Claim a lock
  complete  --agent <name> --cadence <daily|weekly> Mark task as completed (permanent)
  list      [--cadence <daily|weekly>]             Print active lock table
  health    --cadence <daily|weekly>               Probe relay websocket + publish/read health
  dashboard [--port <port>]                        Serve the dashboard (default: ${DEFAULT_DASHBOARD_PORT})
  init      [--force]                              Initialize torch/ directory in current project
  update    [--force]                              Update torch/ configuration (backups, merges)

  list-memories           [--agent <id>] [--type <type>] [--tags <a,b>] [--pinned <true|false>] [--full]
  inspect-memory          --id <memoryId>
  pin-memory              --id <memoryId>
  unpin-memory            --id <memoryId>
  trigger-prune-dry-run   [--retention-ms <ms>]
  memory-stats            [--window-ms <ms>]

Options:
  --dry-run       Build and sign the event but do not publish
  --force         Overwrite existing files (for init) or all files (for update)
  --log-dir       Path to task logs directory (default: task-logs)
  --ignore-logs   Skip checking local logs for completed tasks
  --json          Emit compact single-line JSON
  --json-file     Write JSON output to a file path
  --quiet         Suppress stderr progress logs (pairs well with --json)

Environment:
  NOSTR_LOCK_NAMESPACE      Namespace prefix for lock tags (default: torch)
  NOSTR_LOCK_RELAYS         Comma-separated relay WSS URLs
  NOSTR_LOCK_TTL            Lock TTL in seconds (default: 7200)
  NOSTR_LOCK_QUERY_TIMEOUT_MS   Relay query timeout in milliseconds (default: 15000)
  NOSTR_LOCK_DAILY_ROSTER   Comma-separated daily roster (optional)
  NOSTR_LOCK_WEEKLY_ROSTER  Comma-separated weekly roster (optional)
  TORCH_CONFIG_PATH         Optional path to torch-config.json (default: ./torch-config.json)
  AGENT_PLATFORM            Platform identifier (e.g., codex)

Exit codes:
  0  Success
  1  Usage error
  2  Relay/network error
  3  Lock denied (already locked or race lost)`);
}

/**
 * Main entry point for the torch-lock CLI.
 * Dispatches to specific commands (check, lock, complete, etc.) based on argv.
 *
 * @param {string[]} argv - Arguments from process.argv.slice(2)
 */
export async function main(argv) {
  try {
    const args = parseArgs(argv);

    if (!args.command) {
      usage();
      throw new ExitError(1, 'No command specified');
    }

    switch (args.command) {
      case 'check': {
        if (!args.cadence || !VALID_CADENCES.has(args.cadence)) {
          console.error(`ERROR: --cadence <${[...VALID_CADENCES].join('|')}> is required for check`);
          throw new ExitError(1, 'Missing cadence');
        }
        await cmdCheck(args.cadence, {
          logDir: args.logDir,
          ignoreLogs: args.ignoreLogs,
          json: args.json,
          jsonFile: args.jsonFile,
          quiet: args.quiet,
        });
        break;
      }

      case 'lock': {
        if (!args.agent) {
          console.error('ERROR: --agent <name> is required for lock');
          throw new ExitError(1, 'Missing agent');
        }
        if (!args.cadence || !VALID_CADENCES.has(args.cadence)) {
          console.error(`ERROR: --cadence <${[...VALID_CADENCES].join('|')}> is required for lock`);
          throw new ExitError(1, 'Missing cadence');
        }
        await cmdLock(args.agent, args.cadence, {
          dryRun: args.dryRun,
          platform: args.platform,
          model: args.model
        });
        break;
      }

      case 'complete': {
        if (!args.agent) {
          console.error('ERROR: --agent <name> is required for complete');
          throw new ExitError(1, 'Missing agent');
        }
        if (!args.cadence || !VALID_CADENCES.has(args.cadence)) {
          console.error(`ERROR: --cadence <${[...VALID_CADENCES].join('|')}> is required for complete`);
          throw new ExitError(1, 'Missing cadence');
        }
        await cmdComplete(args.agent, args.cadence, {
          dryRun: args.dryRun,
          platform: args.platform,
          model: args.model
        });
        break;
      }

      case 'list': {
        if (args.cadence && !VALID_CADENCES.has(args.cadence)) {
          console.error(`ERROR: --cadence must be one of: ${[...VALID_CADENCES].join(', ')}`);
          throw new ExitError(1, 'Invalid cadence');
        }
        await cmdList(args.cadence || null);
        break;
      }

      case 'health': {
        if (!args.cadence || !VALID_CADENCES.has(args.cadence)) {
          console.error(`ERROR: --cadence <${[...VALID_CADENCES].join('|')}> is required for health`);
          throw new ExitError(1, 'Missing cadence');
        }
        const result = await runRelayHealthCheck({
          cadence: args.cadence,
          ...(Number.isFinite(args.timeoutMs) ? { timeoutMs: args.timeoutMs } : {}),
          ...(Number.isFinite(args.allRelaysDownMinutes) ? { allRelaysDownMinutes: args.allRelaysDownMinutes } : {}),
          ...(Number.isFinite(args.minSuccessRate) ? { minSuccessRate: args.minSuccessRate } : {}),
          ...(Number.isFinite(args.windowMinutes) ? { windowMinutes: args.windowMinutes } : {}),
        });
        if (!result.ok) {
          result.failureCategory = 'all relays unhealthy';
        }
        console.log(JSON.stringify(result, null, 2));
        if (!result.ok) throw new ExitError(2, 'Relay health check failed');
        break;
      }

      case 'dashboard': {
        await cmdDashboard(args.port);
        break;
      }

      case 'init': {
        await cmdInit(args.force);
        break;
      }

      case 'update': {
        await cmdUpdate(args.force);
        break;
      }

      case 'list-memories': {
        const result = await listMemories({
          agent_id: args.agent,
          type: args.type,
          tags: args.tags,
          pinned: args.pinned,
          limit: args.limit,
          offset: args.offset,
        });

        if (!args.full && Array.isArray(result)) {
          for (const memory of result) {
            if (typeof memory.content === 'string' && memory.content.length > 200) {
              memory.content = memory.content.slice(0, 200) + '... (truncated, use --full to see all)';
            }
          }
        }

        console.log(JSON.stringify(result, null, 2));
        break;
      }

      case 'inspect-memory': {
        if (!args.id) {
          console.error('ERROR: --id <memoryId> is required for inspect-memory');
          throw new ExitError(1, 'Missing memory id');
        }
        const result = await inspectMemory(args.id);
        console.log(JSON.stringify(result, null, 2));
        break;
      }

      case 'pin-memory': {
        if (!args.id) {
          console.error('ERROR: --id <memoryId> is required for pin-memory');
          throw new ExitError(1, 'Missing memory id');
        }
        const result = await pinMemory(args.id);
        console.log(JSON.stringify(result, null, 2));
        break;
      }

      case 'unpin-memory': {
        if (!args.id) {
          console.error('ERROR: --id <memoryId> is required for unpin-memory');
          throw new ExitError(1, 'Missing memory id');
        }
        const result = await unpinMemory(args.id);
        console.log(JSON.stringify(result, null, 2));
        break;
      }

      case 'trigger-prune-dry-run': {
        const result = await triggerPruneDryRun({ retentionMs: args.retentionMs ?? undefined });
        console.log(JSON.stringify(result, null, 2));
        break;
      }

      case 'memory-stats': {
        const result = await memoryStats({ windowMs: args.windowMs ?? undefined });
        console.log(JSON.stringify(result, null, 2));
        break;
      }

      default:
        console.error(`ERROR: Unknown command: ${args.command}`);
        usage();
        throw new ExitError(1, 'Unknown command');
    }
  } catch (err) {
    if (err instanceof ExitError) {
      process.exit(err.code);
    } else {
      console.error(`torch-lock failed: ${err.message}`);
      process.exit(2);
    }
  }
}
