#!/usr/bin/env node
// Source of truth: numbered MUST steps 2 and 4-14 in src/prompts/scheduler-flow.md are
// implemented by this script; step 3 (policy-file read) is best-effort and non-fatal.
import fs from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';

import {
  runCommand,
  parseJsonFromOutput,
  readJson,
  normalizeStringList,
  parseNonNegativeInt,
  parseBooleanFlag,
  excerptText,
  getRunDateKey,
  toYamlScalar,
} from './scheduler-utils.mjs';

import {
  classifyLockBackendError,
  buildLockBackendRemediation,
  runLockHealthPreflight,
  acquireLockWithRetry,
  summarizeLockFailureReasons,
} from './scheduler-lock.mjs';

import { detectPlatform } from '../../src/utils.mjs';

const VALID_CADENCES = new Set(['daily', 'weekly']);
const ALL_EXCLUDED_REASON = 'All roster tasks currently claimed by other agents';
const FAILURE_CATEGORY = {
  PROMPT_PARSE: 'prompt_parse_error',
  PROMPT_SCHEMA: 'prompt_schema_error',
  LOCK_BACKEND: 'lock_backend_error',
  EXECUTION: 'execution_error',
};

function parseArgs(argv) {
  const args = { cadence: null, platform: process.env.AGENT_PLATFORM || detectPlatform() || 'unknown', model: process.env.AGENT_MODEL || null };
  for (let i = 0; i < argv.length; i += 1) {
    const value = argv[i];
    if (!value.startsWith('--') && !args.cadence) {
      args.cadence = value;
      continue;
    }
    if (value === '--cadence') {
      args.cadence = argv[i + 1] || null;
      i += 1;
      continue;
    }
    if (value === '--platform') {
      args.platform = argv[i + 1] || args.platform;
      i += 1;
    }
    if (value === '--model') {
      args.model = argv[i + 1] || args.model;
      i += 1;
    }
  }
  return args;
}

function ts() {
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z').replace(/:/g, '-');
}

function categorizeFailureMetadata(failureCategory, extraMetadata = {}) {
  return {
    failure_category: failureCategory,
    ...extraMetadata,
  };
}

async function validatePromptFile(promptPath) {
  let content;
  try {
    content = await fs.readFile(promptPath, 'utf8');
  } catch (error) {
    return {
      ok: false,
      category: FAILURE_CATEGORY.PROMPT_PARSE,
      reason: 'Prompt file parse/read failed',
      detail: `Prompt not executed; unable to read prompt file at ${promptPath}: ${error.message}`,
    };
  }

  const lines = String(content).split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const firstLine = lines[0] || '';
  if (!firstLine.startsWith('#') && !firstLine.startsWith('>')) {
    return {
      ok: false,
      category: FAILURE_CATEGORY.PROMPT_SCHEMA,
      reason: 'Prompt file schema validation failed',
      detail: `Prompt not executed; expected markdown heading or blockquote on first non-empty line in ${promptPath}.`,
    };
  }

  return { ok: true };
}

async function artifactExistsSince(filePath, sinceMs) {
  if (!filePath) return false;
  const resolved = path.isAbsolute(filePath)
    ? filePath
    : path.resolve(process.cwd(), filePath);
  try {
    const stat = await fs.stat(resolved);
    return stat.isFile() && stat.mtimeMs >= sinceMs;
  } catch {
    return false;
  }
}

async function verifyMemoryStep({ name, markers, artifacts, outputText, sinceMs }) {
  const markerMatched = markers.some((marker) => outputText.includes(marker));
  const artifactResults = await Promise.all(artifacts.map((artifact) => artifactExistsSince(artifact, sinceMs)));
  const artifactMatched = artifactResults.some(Boolean);

  return {
    name,
    markerMatched,
    artifactMatched,
    complete: markerMatched || artifactMatched,
  };
}

function parseFrontmatterAgent(markdown) {
  const lines = markdown.split(/\r?\n/);
  if (lines[0]?.trim() !== '---') return null;
  for (let i = 1; i < lines.length; i += 1) {
    const line = lines[i];
    if (line.trim() === '---') break;
    const match = line.match(/^agent\s*:\s*(.+)$/i);
    if (match?.[1]) {
      return match[1].trim().replace(/^['"]|['"]$/g, '');
    }
  }
  return null;
}

function parseFrontmatterCreatedAt(markdown) {
  const lines = markdown.split(/\r?\n/);
  if (lines[0]?.trim() !== '---') return null;
  for (let i = 1; i < lines.length; i += 1) {
    const line = lines[i];
    if (line.trim() === '---') break;
    const match = line.match(/^created_at\s*:\s*(.+)$/i);
    if (match?.[1]) {
      return match[1].trim().replace(/^['"]|['"]$/g, '');
    }
  }
  return null;
}

function parseDateValue(value) {
  if (!value || typeof value !== 'string') return null;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? ms : null;
}

function parseTimestampFromFilename(filename) {
  const match = String(filename).match(/^(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z)__[^_]+__(completed|failed)\.md$/);
  if (!match?.[1]) return null;
  const iso = match[1].replace(/T(\d{2})-(\d{2})-(\d{2})Z$/, 'T$1:$2:$3Z');
  return parseDateValue(iso);
}

function isStrictSchedulerLogFilename(filename) {
  return /^(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z)__[^_]+__(completed|failed)\.md$/.test(String(filename));
}

function parseAgentFromFilename(filename) {
  const match = String(filename).match(/^.+__([^_]+?)__(completed|failed)\.md$/);
  return match?.[1] || null;
}

async function getLatestFile(logDir) {
  await fs.mkdir(logDir, { recursive: true });
  const entries = await fs.readdir(logDir, { withFileTypes: true });
  const files = entries
    .filter((entry) => entry.isFile())
    .map((entry) => entry.name)
    .filter((filename) => isStrictSchedulerLogFilename(filename))
    .sort((a, b) => b.localeCompare(a));

  const results = await Promise.all(
    files.map(async (filename) => {
      const filePath = path.join(logDir, filename);
      const content = await fs.readFile(filePath, 'utf8').catch(() => '');
      const createdAtMs = parseDateValue(parseFrontmatterCreatedAt(content));
      const fileTimestampMs = parseTimestampFromFilename(filename);
      const effectiveMs = createdAtMs ?? fileTimestampMs;

      if (!effectiveMs) {
        console.warn(`[scheduler] Ignoring invalid log timestamp in ${filename}; checking next candidate.`);
        return null;
      }
      return { filename, effectiveMs };
    }),
  );

  let latest = null;

  for (const result of results) {
    if (!result) continue;
    if (!latest || result.effectiveMs > latest.effectiveMs) {
      latest = result;
    }
  }

  return latest?.filename || null;
}

function selectNextAgent({ roster, excludedSet, previousAgent, firstPrompt }) {
  const previousIndex = roster.indexOf(previousAgent);
  const firstIndex = roster.indexOf(firstPrompt);
  const startIndex = previousIndex >= 0
    ? (previousIndex + 1) % roster.length
    : (firstIndex >= 0 ? firstIndex : 0);

  for (let offset = 0; offset < roster.length; offset += 1) {
    const candidate = roster[(startIndex + offset) % roster.length];
    if (!excludedSet.has(candidate)) {
      return candidate;
    }
  }
  return null;
}

async function getSchedulerConfig(cadence, { isInteractive }) {
  const cfg = await readJson(path.resolve(process.cwd(), 'torch-config.json'), {});
  const scheduler = cfg.scheduler || {};
  const handoffCommand = scheduler.handoffCommandByCadence?.[cadence] || null;
  const missingHandoffCommandForMode = !isInteractive && !handoffCommand;
  const memoryPolicyRaw = scheduler.memoryPolicyByCadence?.[cadence] || {};
  const mode = memoryPolicyRaw.mode === 'required' ? 'required' : 'optional';
  const lockRetryRaw = scheduler.lockRetry || {};
  const maxRetries = parseNonNegativeInt(
    process.env.SCHEDULER_LOCK_MAX_RETRIES,
    parseNonNegativeInt(lockRetryRaw.maxRetries, 2),
  );
  const backoffMs = parseNonNegativeInt(
    process.env.SCHEDULER_LOCK_BACKOFF_MS,
    parseNonNegativeInt(lockRetryRaw.backoffMs, 250),
  );
  const jitterMs = parseNonNegativeInt(
    process.env.SCHEDULER_LOCK_JITTER_MS,
    parseNonNegativeInt(lockRetryRaw.jitterMs, 75),
  );
  const lockHealthPreflightFromConfig = parseBooleanFlag(scheduler.lockHealthPreflight, false);
  const lockHealthPreflightEnabled = parseBooleanFlag(
    process.env.SCHEDULER_LOCK_HEALTH_PREFLIGHT,
    lockHealthPreflightFromConfig,
  );
  const lockHealthPreflightSkip = parseBooleanFlag(process.env.SCHEDULER_SKIP_LOCK_HEALTH_PREFLIGHT, false);
  const strictLock = parseBooleanFlag(
    process.env.SCHEDULER_STRICT_LOCK,
    parseBooleanFlag(scheduler.strict_lock, true),
  );
  const degradedLockRetryWindowMs = parseNonNegativeInt(
    process.env.SCHEDULER_DEGRADED_LOCK_RETRY_WINDOW_MS,
    parseNonNegativeInt(scheduler.degraded_lock_retry_window, 3600000),
  );
  const maxDeferrals = parseNonNegativeInt(
    process.env.SCHEDULER_MAX_DEFERRALS,
    parseNonNegativeInt(scheduler.max_deferrals, 3),
  );

  return {
    firstPrompt: scheduler.firstPromptByCadence?.[cadence] || null,
    handoffCommand,
    missingHandoffCommandForMode,
    validationCommands: Array.isArray(scheduler.validationCommandsByCadence?.[cadence])
      ? scheduler.validationCommandsByCadence[cadence].filter((cmd) => typeof cmd === 'string' && cmd.trim())
      : ['npm run lint'],
    lockRetry: {
      maxRetries,
      backoffMs,
      jitterMs,
    },
    lockHealthPreflight: {
      enabled: lockHealthPreflightEnabled,
      skip: lockHealthPreflightSkip,
    },
    lockFailurePolicy: {
      strictLock,
      degradedLockRetryWindowMs,
      maxDeferrals,
    },
    memoryPolicy: {
      mode,
      retrieveCommand: typeof memoryPolicyRaw.retrieveCommand === 'string' && memoryPolicyRaw.retrieveCommand.trim()
        ? memoryPolicyRaw.retrieveCommand.trim()
        : null,
      storeCommand: typeof memoryPolicyRaw.storeCommand === 'string' && memoryPolicyRaw.storeCommand.trim()
        ? memoryPolicyRaw.storeCommand.trim()
        : null,
      retrieveSuccessMarkers: normalizeStringList(memoryPolicyRaw.retrieveSuccessMarkers, ['MEMORY_RETRIEVED']),
      storeSuccessMarkers: normalizeStringList(memoryPolicyRaw.storeSuccessMarkers, ['MEMORY_STORED']),
      retrieveArtifacts: normalizeStringList(memoryPolicyRaw.retrieveArtifacts),
      storeArtifacts: normalizeStringList(memoryPolicyRaw.storeArtifacts),
    },
  };
}

async function readRunState(cadence) {
  const statePath = path.resolve(process.cwd(), 'task-logs', cadence, '.scheduler-run-state.json');
  const fallback = { run_date: getRunDateKey(), lock_deferral: null };
  const raw = await readJson(statePath, fallback);
  if (!raw || typeof raw !== 'object') {
    return { statePath, state: fallback };
  }

  if (raw.run_date !== getRunDateKey()) {
    return { statePath, state: fallback };
  }

  return {
    statePath,
    state: {
      run_date: raw.run_date,
      lock_deferral: raw.lock_deferral && typeof raw.lock_deferral === 'object' ? raw.lock_deferral : null,
    },
  };
}

async function writeRunState(statePath, state) {
  await fs.mkdir(path.dirname(statePath), { recursive: true });
  await fs.writeFile(statePath, `${JSON.stringify(state, null, 2)}\n`, 'utf8');
}

function createIdempotencyKey({ cadence, selectedAgent, runDate }) {
  return `${cadence}:${selectedAgent}:${runDate}:${randomUUID()}`;
}

async function writeLog({ cadence, agent, status, reason, detail, platform, metadata = {} }) {
  const logDir = path.resolve(process.cwd(), 'task-logs', cadence);
  await fs.mkdir(logDir, { recursive: true });
  const file = `${ts()}__${agent}__${status}.md`;
  const mergedMetadata = {
    platform: platform || process.env.AGENT_PLATFORM || 'unknown',
    ...metadata,
  };

  const body = [
    '---',
    `cadence: ${cadence}`,
    `agent: ${agent}`,
    `status: ${status}`,
    `reason: ${toYamlScalar(reason)}`,
    detail ? `detail: ${toYamlScalar(detail)}` : null,
    `created_at: ${new Date().toISOString()}`,
    `timestamp: ${new Date().toISOString()}`,
    ...Object.entries(mergedMetadata)
      .filter(([, value]) => value !== undefined && value !== null && value !== '')
      .map(([key, value]) => `${key}: ${toYamlScalar(value)}`),
    '---',
    '',
    `# Scheduler ${status}`,
    '',
    `- reason: ${reason}`,
    detail ? `- detail: ${detail}` : null,
    ...Object.entries(mergedMetadata)
      .filter(([, value]) => value !== undefined && value !== null && value !== '')
      .map(([key, value]) => `- ${key}: ${value}`),
    '',
  ].filter(Boolean).join('\n');
  await fs.writeFile(path.join(logDir, file), body, 'utf8');
  return file;
}

async function main() {
  const { cadence, platform, model } = parseArgs(process.argv.slice(2));
  if (!VALID_CADENCES.has(cadence)) {
    console.error('Usage: node scripts/agent/run-scheduler-cycle.mjs <daily|weekly>');
    process.exit(1);
  }

  const roster = (await readJson(path.resolve(process.cwd(), 'src/prompts/roster.json'), {}))[cadence] || [];
  if (!Array.isArray(roster) || roster.length === 0) {
    console.error(`No roster entries for cadence ${cadence}`);
    process.exit(1);
  }

  const isInteractive = Boolean(process.stdin.isTTY && process.stdout.isTTY);
  const schedulerConfig = await getSchedulerConfig(cadence, { isInteractive });
  const logDir = path.resolve(process.cwd(), 'task-logs', cadence);

  const agentsPath = path.resolve(process.cwd(), 'AGENTS.md');
  try {
    const agentsContent = await fs.readFile(agentsPath, 'utf8');
    process.stdout.write(`${agentsContent}\n`);
  } catch {
    console.log('No AGENTS.md found; continuing');
  }

  while (true) {
    const { statePath: runStatePath, state: schedulerRunState } = await readRunState(cadence);

    if (schedulerConfig.lockHealthPreflight.enabled && !schedulerConfig.lockHealthPreflight.skip) {
      const preflight = await runLockHealthPreflight({ cadence, platform });
      if (preflight.code !== 0) {
        const allRelaysUnhealthy = Boolean(preflight.payload?.summary?.allRelaysUnhealthy);
        const incidentSignal = preflight.payload?.incidentSignal || null;
        await writeLog({
          cadence,
          agent: 'scheduler',
          status: allRelaysUnhealthy ? 'deferred' : 'failed',
          platform,
          reason: allRelaysUnhealthy
            ? 'All relays unhealthy preflight'
            : 'Lock backend unavailable preflight',
          detail: allRelaysUnhealthy
            ? `Deferred run before lock acquisition: ${incidentSignal?.reason || 'all relays unhealthy'}. Prompt not executed. ${buildLockBackendRemediation({ cadence, retryWindowMs: schedulerConfig.lockFailurePolicy.degradedLockRetryWindowMs, maxDeferrals: schedulerConfig.lockFailurePolicy.maxDeferrals, incidentSignalId: incidentSignal?.id || null })}`
            : `Preflight failed (${preflight.failureCategory}). Prompt not executed. ${buildLockBackendRemediation({ cadence, retryWindowMs: schedulerConfig.lockFailurePolicy.degradedLockRetryWindowMs, maxDeferrals: schedulerConfig.lockFailurePolicy.maxDeferrals, incidentSignalId: incidentSignal?.id || null })}`,
          metadata: {
            ...categorizeFailureMetadata(FAILURE_CATEGORY.LOCK_BACKEND, { failure_class: 'backend_unavailable' }),
            preflight_failure_category: preflight.failureCategory,
            relay_list: preflight.relayList.join(', ') || '(none)',
            preflight_stderr_excerpt: preflight.stderrExcerpt || '(empty)',
            preflight_stdout_excerpt: preflight.stdoutExcerpt || '(empty)',
            incident_signal_id: incidentSignal?.id || null,
            incident_signal_severity: incidentSignal?.severity || null,
            preflight_alerts: JSON.stringify(preflight.payload?.alerts || []),
            relay_health_history_path: preflight.payload?.historyPath || null,
          },
        });
        process.exit(allRelaysUnhealthy ? 0 : (preflight.code || 1));
      }
    }

    const checkResult = await runCommand('npm', ['run', `lock:check:${cadence}`, '--', '--json', '--quiet']);
    const checkPayload = parseJsonFromOutput(`${checkResult.stdout}\n${checkResult.stderr}`) || {};
    const excluded = Array.isArray(checkPayload.excluded)
      ? checkPayload.excluded
      : [...new Set([
          ...(Array.isArray(checkPayload.locked) ? checkPayload.locked : []),
          ...(Array.isArray(checkPayload.paused) ? checkPayload.paused : []),
          ...(Array.isArray(checkPayload.completed) ? checkPayload.completed : []),
        ])];
    const excludedSet = new Set(excluded);

    const latestFile = await getLatestFile(logDir);
    let previousAgent = null;

    if (latestFile) {
      const latestPath = path.join(logDir, latestFile);
      const content = await fs.readFile(latestPath, 'utf8').catch(() => '');
      previousAgent = parseFrontmatterAgent(content) || parseAgentFromFilename(latestFile);
      if (!roster.includes(previousAgent)) {
        previousAgent = null;
      }
    }

    const selectedAgent = selectNextAgent({
      roster,
      excludedSet,
      previousAgent,
      firstPrompt: schedulerConfig.firstPrompt,
    });

    if (!selectedAgent) {
      await writeLog({
        cadence,
        agent: 'scheduler',
        status: 'failed',
        platform,
        reason: ALL_EXCLUDED_REASON,
      });
      process.exit(1);
    }

    const deferralForAgent = schedulerRunState.lock_deferral?.selected_agent === selectedAgent
      ? schedulerRunState.lock_deferral
      : null;

    const lockAttempt = await acquireLockWithRetry({
      selectedAgent,
      cadence,
      platform,
      model,
      lockRetry: schedulerConfig.lockRetry,
      idempotencyKey: deferralForAgent?.idempotency_key,
    });
    const lockResult = lockAttempt.result;

    if (lockResult.code === 3) {
      continue;
    }

    if (lockResult.code === 2) {
      const combinedLockOutput = `${lockResult.stderr}\n${lockResult.stdout}`;
      const diagnosticsSummary = summarizeLockFailureReasons(combinedLockOutput);
      const backendCategory = lockAttempt.finalBackendCategory || classifyLockBackendError(combinedLockOutput);
      const modelPart = model ? ` --model ${model}` : '';
      const lockCommand = `AGENT_PLATFORM=${platform} npm run lock:lock -- --agent ${selectedAgent} --cadence ${cadence}${modelPart}`;
      const stderrExcerpt = excerptText(lockResult.stderr);
      const stdoutExcerpt = excerptText(lockResult.stdout);
      const backoffSchedule = lockAttempt.backoffScheduleMs.join(', ');

      const existingDeferral = deferralForAgent || {};
      const firstFailureAt = existingDeferral.first_failure_timestamp || new Date().toISOString();
      const firstFailureMs = parseDateValue(firstFailureAt) || Date.now();
      const nowMs = Date.now();
      const deferralAttemptCount = parseNonNegativeInt(existingDeferral.attempt_count, 0) + 1;
      const idempotencyKey = existingDeferral.idempotency_key
        || createIdempotencyKey({ cadence, selectedAgent, runDate: schedulerRunState.run_date });
      const withinRetryWindow = nowMs - firstFailureMs <= schedulerConfig.lockFailurePolicy.degradedLockRetryWindowMs;
      const withinDeferralBudget = deferralAttemptCount <= schedulerConfig.lockFailurePolicy.maxDeferrals;

      if (!schedulerConfig.lockFailurePolicy.strictLock && withinRetryWindow && withinDeferralBudget) {
        schedulerRunState.lock_deferral = {
          attempt_count: deferralAttemptCount,
          first_failure_timestamp: firstFailureAt,
          backend_category: backendCategory,
          idempotency_key: idempotencyKey,
          selected_agent: selectedAgent,
        };
        await writeRunState(runStatePath, schedulerRunState);
        await writeLog({
          cadence,
          agent: selectedAgent,
          status: 'deferred',
          platform,
          reason: 'Lock backend deferred',
          detail: `Deferred after lock backend failure (${backendCategory}); retry window active and deferral budget remaining. Prompt not executed. ${buildLockBackendRemediation({ cadence, retryWindowMs: schedulerConfig.lockFailurePolicy.degradedLockRetryWindowMs, maxDeferrals: schedulerConfig.lockFailurePolicy.maxDeferrals })}`,
          metadata: {
            ...categorizeFailureMetadata(FAILURE_CATEGORY.LOCK_BACKEND, { failure_class: 'backend_unavailable' }),
            deferral_attempt_count: deferralAttemptCount,
            deferral_first_failure_timestamp: firstFailureAt,
            backend_category: backendCategory,
            lock_idempotency_key: idempotencyKey,
          },
        });
        process.exit(0);
      }

      schedulerRunState.lock_deferral = null;
      await writeRunState(runStatePath, schedulerRunState);
      await writeLog({
        cadence,
        agent: selectedAgent,
        status: 'failed',
        platform,
        reason: 'Lock backend error',
        detail: `Lock backend error (${backendCategory}) after ${lockAttempt.attempts} attempt(s). Prompt not executed. ${buildLockBackendRemediation({ cadence, retryWindowMs: schedulerConfig.lockFailurePolicy.degradedLockRetryWindowMs, maxDeferrals: schedulerConfig.lockFailurePolicy.maxDeferrals })}`,
        metadata: {
          ...categorizeFailureMetadata(FAILURE_CATEGORY.LOCK_BACKEND, { failure_class: 'backend_unavailable' }),
          lock_attempts_total: lockAttempt.attempts,
          lock_backoff_schedule_ms: backoffSchedule || '(none)',
          lock_correlation_id: diagnosticsSummary.correlationId || lockAttempt.correlationId,
          lock_attempt_id: diagnosticsSummary.attemptId || String(lockAttempt.attempts),
          lock_total_retry_timeline_ms: diagnosticsSummary.totalElapsedMs,
          lock_failure_reason_distribution: JSON.stringify(diagnosticsSummary.reasonDistribution),
          backend_category: backendCategory,
          deferral_attempt_count: deferralAttemptCount,
          deferral_first_failure_timestamp: firstFailureAt,
          lock_command: lockCommand,
          lock_idempotency_key: idempotencyKey,
          lock_stderr_excerpt: stderrExcerpt || '(empty)',
          lock_stdout_excerpt: stdoutExcerpt || '(empty)',
        },
      });
      process.exit(2);
    }

    if (lockResult.code !== 0) {
      schedulerRunState.lock_deferral = null;
      await writeRunState(runStatePath, schedulerRunState);
      await writeLog({
        cadence,
        agent: selectedAgent,
        status: 'failed',
        platform,
        reason: 'Failed to acquire lock',
      });
      process.exit(lockResult.code);
    }

    const promptPath = path.resolve(process.cwd(), 'src/prompts', cadence, `${selectedAgent}.md`);
    const promptValidation = await validatePromptFile(promptPath);
    if (!promptValidation.ok) {
      await writeLog({
        cadence,
        agent: selectedAgent,
        status: 'failed',
        platform,
        reason: promptValidation.reason,
        detail: promptValidation.detail,
        metadata: categorizeFailureMetadata(promptValidation.category, { prompt_path: promptPath }),
      });
      process.exit(1);
    }

    schedulerRunState.lock_deferral = null;
    await writeRunState(runStatePath, schedulerRunState);
    const runArtifactSince = new Date().toISOString();
    const runStartMs = Date.parse(runArtifactSince);
    const outputChunks = [];

    const memoryDir = path.resolve(process.cwd(), 'memory-updates');
    await fs.mkdir(memoryDir, { recursive: true });
    const memoryFile = path.join(memoryDir, `${ts()}__${selectedAgent}.md`);
    const schedulerEnv = {
      AGENT_PLATFORM: platform,
      ...(model ? { AGENT_MODEL: model } : {}),
      SCHEDULER_AGENT: selectedAgent,
      SCHEDULER_CADENCE: cadence,
      SCHEDULER_PROMPT_PATH: promptPath,
      SCHEDULER_MEMORY_FILE: memoryFile,
    };

    if (schedulerConfig.memoryPolicy.retrieveCommand) {
      const retrieveResult = await runCommand('bash', ['-lc', schedulerConfig.memoryPolicy.retrieveCommand], {
        env: schedulerEnv,
      });
      outputChunks.push(retrieveResult.stdout, retrieveResult.stderr);
      if (retrieveResult.code !== 0) {
        await writeLog({
          cadence,
          agent: selectedAgent,
          status: 'failed',
          platform,
          reason: 'Memory retrieval command failed',
          detail: schedulerConfig.memoryPolicy.retrieveCommand,
          metadata: categorizeFailureMetadata(FAILURE_CATEGORY.EXECUTION, { failure_class: 'prompt_validation_error' }),
        });
        process.exit(retrieveResult.code);
      }
    }

    if (schedulerConfig.handoffCommand) {
      const handoff = await runCommand('bash', ['-lc', schedulerConfig.handoffCommand], {
        env: schedulerEnv,
      });
      outputChunks.push(handoff.stdout, handoff.stderr);
      if (handoff.code !== 0) {
        await writeLog({
          cadence,
          agent: selectedAgent,
          status: 'failed',
          platform,
          reason: 'Prompt/handoff execution failed',
          detail: 'Handoff callback failed.',
          metadata: categorizeFailureMetadata(FAILURE_CATEGORY.EXECUTION, { failure_class: 'prompt_validation_error' }),
        });
        process.exit(handoff.code);
      }
    } else {
      const detail = schedulerConfig.missingHandoffCommandForMode
        ? 'Missing scheduler handoff command for non-interactive run. Set scheduler.handoffCommandByCadence.daily|weekly in torch-config.json.'
        : 'No handoff callback configured. Set scheduler.handoffCommandByCadence.daily|weekly in torch-config.json.';
      await writeLog({
        cadence,
        agent: selectedAgent,
        status: 'failed',
        platform,
        reason: 'Prompt/handoff execution failed',
        detail,
        metadata: categorizeFailureMetadata(FAILURE_CATEGORY.EXECUTION, { failure_class: 'prompt_validation_error' }),
      });
      process.exit(1);
    }

    if (schedulerConfig.memoryPolicy.storeCommand) {
      const storeResult = await runCommand('bash', ['-lc', schedulerConfig.memoryPolicy.storeCommand], {
        env: schedulerEnv,
      });
      outputChunks.push(storeResult.stdout, storeResult.stderr);
      if (storeResult.code !== 0) {
        await writeLog({
          cadence,
          agent: selectedAgent,
          status: 'failed',
          platform,
          reason: 'Memory storage command failed',
          detail: schedulerConfig.memoryPolicy.storeCommand,
          metadata: categorizeFailureMetadata(FAILURE_CATEGORY.EXECUTION, { failure_class: 'prompt_validation_error' }),
        });
        process.exit(storeResult.code);
      }
    }

    const memoryOutput = outputChunks.join('\n');
    const retrieveCheck = await verifyMemoryStep({
      name: 'retrieve',
      markers: schedulerConfig.memoryPolicy.retrieveSuccessMarkers,
      artifacts: schedulerConfig.memoryPolicy.retrieveArtifacts,
      outputText: memoryOutput,
      sinceMs: runStartMs,
    });
    const storeCheck = await verifyMemoryStep({
      name: 'store',
      markers: schedulerConfig.memoryPolicy.storeSuccessMarkers,
      artifacts: schedulerConfig.memoryPolicy.storeArtifacts,
      outputText: memoryOutput,
      sinceMs: runStartMs,
    });

    const missingSteps = [retrieveCheck, storeCheck].filter((step) => !step.complete).map((step) => step.name);
    if (missingSteps.length && schedulerConfig.memoryPolicy.mode === 'required') {
      await writeLog({
        cadence,
        agent: selectedAgent,
        status: 'failed',
        platform,
        reason: 'Required memory steps not verified',
        detail: `Missing evidence for: ${missingSteps.join(', ')}`,
        metadata: categorizeFailureMetadata(FAILURE_CATEGORY.PROMPT_SCHEMA, { failure_class: 'prompt_validation_error' }),
      });
      process.exit(1);
    }

    if (missingSteps.length) {
      console.warn(`[scheduler] Optional memory evidence missing for ${missingSteps.join(', ')}.`);
    }

    const artifactCheck = await runCommand('node', [
      'scripts/agent/verify-run-artifacts.mjs',
      '--since',
      runArtifactSince,
      '--agent',
      selectedAgent,
      '--cadence',
      cadence,
      '--prompt-path',
      promptPath,
      '--run-start',
      runArtifactSince,
      '--check-failure-notes',
    ]);
    if (artifactCheck.code !== 0) {
      const detail = artifactCheck.stderr.trim() || artifactCheck.stdout.trim() || 'Artifact verification failed.';
      await writeLog({
        cadence,
        agent: selectedAgent,
        status: 'failed',
        platform,
        reason: 'Missing required run artifacts',
        detail,
        metadata: categorizeFailureMetadata(FAILURE_CATEGORY.PROMPT_SCHEMA, { failure_class: 'prompt_validation_error' }),
      });
      process.exit(artifactCheck.code);
    }

    for (const validation of schedulerConfig.validationCommands) {
      const parts = validation.split(' ').filter(Boolean);
      if (!parts.length) continue;
      const result = await runCommand(parts[0], parts.slice(1));
      if (result.code !== 0) {
        await writeLog({
          cadence,
          agent: selectedAgent,
          status: 'failed',
          platform,
          reason: 'Validation failed',
          detail: validation,
          metadata: categorizeFailureMetadata(FAILURE_CATEGORY.EXECUTION, { failure_class: 'prompt_validation_error' }),
        });
        process.exit(result.code);
      }
    }

    const completeResult = await runCommand(
      'npm',
      ['run', 'lock:complete', '--', '--agent', selectedAgent, '--cadence', cadence, ...(model ? ['--model', model] : [])],
      { env: { AGENT_PLATFORM: platform, ...(model ? { AGENT_MODEL: model } : {}) } },
    );

    if (completeResult.code !== 0) {
      await writeLog({
        cadence,
        agent: selectedAgent,
        status: 'failed',
        platform,
        reason: `Completion publish failed. Retry npm run lock:complete -- --agent ${selectedAgent} --cadence ${cadence} after verifying relay connectivity`,
      });
      process.exit(completeResult.code);
    }

    await writeLog({ cadence, agent: selectedAgent, status: 'completed', platform, reason: 'Scheduler cycle completed successfully' });
    process.exit(0);
  }
}

main().catch(async (err) => {
  console.error(err);
  process.exit(1);
});
