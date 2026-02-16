import { SimplePool } from 'nostr-tools/pool';
import {
  getQueryTimeoutMs,
  getPublishTimeoutMs,
  getMinSuccessfulRelayPublishes,
  getRelayFallbacks,
  getMinActiveRelayPool,
} from './torch-config.mjs';
import { KIND_APP_DATA } from './constants.mjs';

const relayHealthState = {
  metricsByRelay: new Map(),
  lastSnapshotAt: 0,
};

function nowUnix() {
  return Math.floor(Date.now() / 1000);
}

export function parseLockEvent(event) {
  const dTag = event.tags.find((t) => t[0] === 'd')?.[1] ?? '';
  const expTag = event.tags.find((t) => t[0] === 'expiration')?.[1];
  const expiresAt = expTag ? parseInt(expTag, 10) : null;

  let content = {};
  try {
    const parsed = JSON.parse(event.content);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      content = parsed;
    }
  } catch {
    // Ignore malformed JSON content
  }

  return {
    eventId: event.id,
    pubkey: event.pubkey,
    createdAt: event.created_at,
    createdAtIso: new Date(event.created_at * 1000).toISOString(),
    expiresAt,
    expiresAtIso: expiresAt ? new Date(expiresAt * 1000).toISOString() : null,
    dTag,
    agent: content.agent ?? null,
    cadence: content.cadence ?? null,
    status: content.status ?? null,
    date: content.date ?? null,
    platform: content.platform ?? null,
  };
}

function filterActiveLocks(locks) {
  const now = nowUnix();
  return locks.filter((lock) => !lock.expiresAt || lock.expiresAt > now);
}

function withTimeout(promise, timeoutMs, timeoutMessage) {
  let timeoutHandle;
  const timeoutPromise = new Promise((_, reject) => {
    timeoutHandle = setTimeout(() => reject(new Error(timeoutMessage)), timeoutMs);
  });
  return Promise.race([promise, timeoutPromise]).finally(() => {
    if (timeoutHandle) clearTimeout(timeoutHandle);
  });
}

function relayListLabel(relays) {
  return relays.join(', ');
}

function classifyPublishError(message) {
  const normalized = String(message || '').toLowerCase();
  if (normalized.includes('publish timed out after') || normalized.includes('publish timeout')) {
    return 'publish_timeout';
  }
  if (
    normalized.includes('enotfound')
    || normalized.includes('eai_again')
    || normalized.includes('getaddrinfo')
    || (normalized.includes('dns') && normalized.includes('websocket'))
  ) {
    return 'dns_resolution';
  }
  if (
    normalized.includes('connect etimedout')
    || normalized.includes('tcp connect timed out')
    || normalized.includes('connect timeout')
  ) {
    return 'tcp_connect_timeout';
  }
  if (
    normalized.includes('tls')
    || normalized.includes('ssl')
    || normalized.includes('certificate')
    || normalized.includes('handshake')
  ) {
    return 'tls_handshake';
  }
  if (
    normalized.includes('websocket')
    || normalized.includes('bad response')
    || normalized.includes('unexpected server response')
  ) {
    return 'websocket_open_failure';
  }
  if (normalized.includes('timed out') || normalized.includes('timeout') || normalized.includes('etimedout')) {
    return 'network_timeout';
  }
  if (normalized.includes('econnreset') || normalized.includes('connection reset') || normalized.includes('socket hang up')) {
    return 'connection_reset';
  }
  if (
    normalized.includes('unavailable')
    || normalized.includes('offline')
    || normalized.includes('econnrefused')
    || normalized.includes('connection refused')
    || normalized.includes('enotfound')
    || normalized.includes('503')
  ) {
    return 'relay_unavailable';
  }
  return 'permanent_validation_error';
}

function isTransientPublishCategory(category) {
  return [
    'publish_timeout',
    'dns_resolution',
    'tcp_connect_timeout',
    'tls_handshake',
    'websocket_open_failure',
    'network_timeout',
    'connection_reset',
    'relay_unavailable',
  ].includes(category);
}

function calculateBackoffDelayMs(attemptNumber, baseMs, capMs, randomFn = Math.random) {
  const maxDelay = Math.min(capMs, baseMs * (2 ** Math.max(0, attemptNumber - 1)));
  return Math.floor(randomFn() * maxDelay);
}

function ensureRelayMetrics(relay, config) {
  let metrics = relayHealthState.metricsByRelay.get(relay);
  if (!metrics) {
    metrics = {
      relay,
      recentOutcomes: [],
      failureStreak: 0,
      quarantineUntil: 0,
      cooldownMs: config.quarantineCooldownMs,
      lastLatencyMs: null,
      lastResultAt: null,
    };
    relayHealthState.metricsByRelay.set(relay, metrics);
  }
  return metrics;
}

function summarizeRelayMetrics(metrics, nowMs) {
  const total = metrics.recentOutcomes.length;
  const successCount = metrics.recentOutcomes.filter((entry) => entry.success).length;
  const timeoutCount = metrics.recentOutcomes.filter((entry) => entry.timedOut).length;
  const latencyEntries = metrics.recentOutcomes.map((entry) => entry.latencyMs).filter((v) => Number.isFinite(v));
  const averageLatencyMs = latencyEntries.length
    ? Math.round(latencyEntries.reduce((sum, value) => sum + value, 0) / latencyEntries.length)
    : null;
  const successRate = total > 0 ? successCount / total : 0.5;
  const timeoutRate = total > 0 ? timeoutCount / total : 0;
  const quarantineRemainingMs = metrics.quarantineUntil > nowMs ? metrics.quarantineUntil - nowMs : 0;
  return {
    relay: metrics.relay,
    sampleSize: total,
    successRate,
    timeoutRate,
    averageLatencyMs,
    failureStreak: metrics.failureStreak,
    quarantined: quarantineRemainingMs > 0,
    quarantineRemainingMs,
    cooldownMs: metrics.cooldownMs,
    lastResultAt: metrics.lastResultAt,
  };
}

function computeRelayScore(summary) {
  const latencyPenalty = summary.averageLatencyMs === null
    ? 0.1
    : Math.min(0.35, summary.averageLatencyMs / 10_000);
  const quarantinePenalty = summary.quarantined ? 1 : 0;
  return (summary.successRate * 1.4) - (summary.timeoutRate * 0.9) - latencyPenalty - quarantinePenalty;
}

function rankRelaysByHealth(relays, config, nowMs = Date.now()) {
  const summaries = relays.map((relay) => {
    const metrics = ensureRelayMetrics(relay, config);
    const summary = summarizeRelayMetrics(metrics, nowMs);
    return {
      relay,
      summary,
      score: computeRelayScore(summary),
    };
  });

  return summaries.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    if (a.summary.quarantined !== b.summary.quarantined) return a.summary.quarantined ? 1 : -1;
    if (a.summary.averageLatencyMs !== b.summary.averageLatencyMs) {
      if (a.summary.averageLatencyMs === null) return 1;
      if (b.summary.averageLatencyMs === null) return -1;
      return a.summary.averageLatencyMs - b.summary.averageLatencyMs;
    }
    return a.relay.localeCompare(b.relay);
  });
}

function prioritizeRelays(relays, config, nowMs = Date.now()) {
  const minActive = Math.max(1, Math.min(config.minActiveRelayPool, relays.length || 1));
  const ranked = rankRelaysByHealth([...new Set(relays)], config, nowMs);
  const active = ranked.filter((entry) => !entry.summary.quarantined);
  const quarantined = ranked
    .filter((entry) => entry.summary.quarantined)
    .sort((a, b) => a.summary.quarantineRemainingMs - b.summary.quarantineRemainingMs);

  const selected = [...active];
  if (selected.length < minActive) {
    const additionalNeeded = Math.min(minActive - selected.length, quarantined.length);
    selected.push(...quarantined.slice(0, additionalNeeded));
  }

  return {
    prioritized: selected.map((entry) => entry.relay),
    ranked,
  };
}

function recordRelayOutcome(relay, success, errorMessage, latencyMs, config, nowMs = Date.now()) {
  const metrics = ensureRelayMetrics(relay, config);
  const timedOut = String(errorMessage || '').toLowerCase().includes('timeout')
    || String(errorMessage || '').toLowerCase().includes('timed out');
  metrics.recentOutcomes.push({ success, timedOut, latencyMs, atMs: nowMs });
  if (metrics.recentOutcomes.length > config.rollingWindowSize) {
    metrics.recentOutcomes.splice(0, metrics.recentOutcomes.length - config.rollingWindowSize);
  }
  metrics.lastResultAt = nowMs;
  metrics.lastLatencyMs = Number.isFinite(latencyMs) ? latencyMs : null;

  if (success) {
    metrics.failureStreak = 0;
    if (metrics.quarantineUntil > nowMs) {
      metrics.quarantineUntil = 0;
      metrics.cooldownMs = config.quarantineCooldownMs;
    }
    return;
  }

  metrics.failureStreak += 1;
  if (metrics.failureStreak >= config.failureThreshold) {
    metrics.quarantineUntil = nowMs + metrics.cooldownMs;
    metrics.cooldownMs = Math.min(config.maxQuarantineCooldownMs, Math.floor(metrics.cooldownMs * 1.5));
  }
}

function collectHealthSnapshot(relays, config, nowMs = Date.now()) {
  const uniqueRelays = [...new Set(relays)];
  return rankRelaysByHealth(uniqueRelays, config, nowMs).map((entry) => ({
    relay: entry.relay,
    score: Number(entry.score.toFixed(4)),
    ...entry.summary,
  }));
}

function maybeLogHealthSnapshot(relays, config, logger, reason, force = false, nowMs = Date.now()) {
  const intervalReached = nowMs - relayHealthState.lastSnapshotAt >= config.snapshotIntervalMs;
  if (!force && !intervalReached) return;
  relayHealthState.lastSnapshotAt = nowMs;
  logger(JSON.stringify({
    event: 'relay_health_snapshot',
    reason,
    relays: collectHealthSnapshot(relays, config, nowMs),
  }));
}

function buildRelayHealthConfig(deps) {
  return {
    rollingWindowSize: deps.rollingWindowSize ?? 25,
    failureThreshold: deps.failureThreshold ?? 3,
    quarantineCooldownMs: deps.quarantineCooldownMs ?? 30_000,
    maxQuarantineCooldownMs: deps.maxQuarantineCooldownMs ?? 5 * 60_000,
    snapshotIntervalMs: deps.snapshotIntervalMs ?? 60_000,
    minActiveRelayPool: Math.max(1, deps.minActiveRelayPool),
  };
}

function mergeRelayList(primaryRelays, fallbackRelays) {
  return [...new Set([...primaryRelays, ...fallbackRelays])];
}

export async function queryLocks(relays, cadence, dateStr, namespace, deps = {}) {
  const {
    poolFactory = () => new SimplePool(),
    getQueryTimeoutMsFn = getQueryTimeoutMs,
    getRelayFallbacksFn = getRelayFallbacks,
    getMinActiveRelayPoolFn = getMinActiveRelayPool,
    errorLogger = console.error,
    healthLogger = console.error,
  } = deps;

  const pool = poolFactory();
  const tagFilter = `${namespace}-lock-${cadence}-${dateStr}`;
  const queryTimeoutMs = getQueryTimeoutMsFn();
  const fallbackRelays = getRelayFallbacksFn().filter((relay) => !relays.includes(relay));
  const healthConfig = buildRelayHealthConfig({
    ...deps,
    minActiveRelayPool: getMinActiveRelayPoolFn(),
  });

  const runQuery = async (relaySet, phase) => {
    const { prioritized } = prioritizeRelays(relaySet, healthConfig);
    if (prioritized.length > 0) {
      errorLogger(`[${phase}] Querying ${prioritized.length} relays (${relayListLabel(prioritized)})...`);
    }

    const startedAtMs = Date.now();
    try {
      const events = await withTimeout(
        pool.querySync(prioritized, {
          kinds: [KIND_APP_DATA],
          '#t': [tagFilter],
        }),
        queryTimeoutMs,
        `[${phase}] Relay query timed out after ${queryTimeoutMs}ms (relays: ${relayListLabel(prioritized)})`,
      );
      const elapsedMs = Date.now() - startedAtMs;
      for (const relay of prioritized) {
        recordRelayOutcome(relay, true, null, elapsedMs, healthConfig);
      }
      return filterActiveLocks(events.map(parseLockEvent));
    } catch (err) {
      const elapsedMs = Date.now() - startedAtMs;
      const message = err instanceof Error ? err.message : String(err);
      for (const relay of prioritized) {
        recordRelayOutcome(relay, false, message, elapsedMs, healthConfig);
      }
      throw new Error(
        `[${phase}] Relay query failed (timeout=${queryTimeoutMs}ms, relays=${relayListLabel(prioritized)}): ${message}`,
        { cause: err },
      );
    }
  };

  const allRelays = mergeRelayList(relays, fallbackRelays);

  try {
    maybeLogHealthSnapshot(allRelays, healthConfig, healthLogger, 'query:periodic');
    try {
      return await runQuery(relays, 'query:primary');
    } catch (primaryErr) {
      if (!fallbackRelays.length) {
        maybeLogHealthSnapshot(allRelays, healthConfig, healthLogger, 'query:failure', true);
        throw primaryErr;
      }
      errorLogger(`WARN: ${primaryErr.message}`);
      errorLogger(`WARN: retrying query with fallback relays (${relayListLabel(fallbackRelays)})`);
      return await runQuery(fallbackRelays, 'query:fallback');
    }
  } finally {
    pool.close(allRelays);
  }
}

async function publishToRelays(pool, relays, event, publishTimeoutMs, phase) {
  const publishPromises = pool.publish(relays, event);
  const settled = await Promise.allSettled(
    publishPromises.map((publishPromise, index) => withTimeout(
      publishPromise,
      publishTimeoutMs,
      `[${phase}] Publish timed out after ${publishTimeoutMs}ms (relay=${relays[index]})`,
    )),
  );

  return settled.map((result, index) => {
    if (result.status === 'fulfilled') {
      return {
        relay: relays[index],
        success: true,
        phase,
        latencyMs: null,
      };
    }
    const reason = result.reason;
    const message = reason instanceof Error ? reason.message : String(reason ?? 'unknown');
    return {
      relay: relays[index],
      success: false,
      phase,
      message,
      latencyMs: null,
    };
  });
}

export async function publishLock(relays, event, deps = {}) {
  const {
    poolFactory = () => new SimplePool(),
    getPublishTimeoutMsFn = getPublishTimeoutMs,
    getMinSuccessfulRelayPublishesFn = getMinSuccessfulRelayPublishes,
    getRelayFallbacksFn = getRelayFallbacks,
    getMinActiveRelayPoolFn = getMinActiveRelayPool,
    retryAttempts = 4,
    retryBaseDelayMs = 500,
    retryCapDelayMs = 8_000,
    sleepFn = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
    randomFn = Math.random,
    telemetryLogger = console.error,
    healthLogger = console.error,
    diagnostics = {},
  } = deps;

  const correlationId = diagnostics.correlationId || process.env.SCHEDULER_LOCK_CORRELATION_ID || 'none';
  const attemptId = diagnostics.attemptId || process.env.SCHEDULER_LOCK_ATTEMPT_ID || '1';

  const pool = poolFactory();
  const publishTimeoutMs = getPublishTimeoutMsFn();
  const minSuccesses = getMinSuccessfulRelayPublishesFn();
  const fallbackRelays = getRelayFallbacksFn().filter((relay) => !relays.includes(relay));
  const maxAttempts = Math.max(1, Math.floor(retryAttempts));
  const healthConfig = buildRelayHealthConfig({
    ...deps,
    minActiveRelayPool: getMinActiveRelayPoolFn(),
  });

  const publishOnce = async () => {
    const attempted = new Set();
    const publishResults = [];

    const attemptPhase = async (phaseRelays, phaseName) => {
      if (!phaseRelays.length) return;
      const { prioritized } = prioritizeRelays(phaseRelays, healthConfig);
      if (!prioritized.length) return;

      console.error(`[${phaseName}] Publishing to ${prioritized.length} relays (${prioritized.join(', ')})...`);

      const startedAtMs = Date.now();
      for (const relay of prioritized) {
        attempted.add(relay);
      }
      const phaseResults = await publishToRelays(pool, prioritized, event, publishTimeoutMs, phaseName);
      const elapsedMs = Date.now() - startedAtMs;
      for (const result of phaseResults) {
        result.latencyMs = elapsedMs;
        recordRelayOutcome(result.relay, result.success, result.message, elapsedMs, healthConfig);
      }
      publishResults.push(...phaseResults);
    };

    await attemptPhase(relays, 'publish:primary');

    let successCount = publishResults.filter((result) => result.success).length;
    if (successCount < minSuccesses && fallbackRelays.length > 0) {
      await attemptPhase(fallbackRelays, 'publish:fallback');
      successCount = publishResults.filter((result) => result.success).length;
    }

    const failures = publishResults
      .filter((result) => !result.success)
      .map((result) => ({
        ...result,
        category: classifyPublishError(result.message),
      }));

    return { attempted, publishResults, successCount, failures };
  };

  const allRelays = mergeRelayList(relays, fallbackRelays);

  try {
    maybeLogHealthSnapshot(allRelays, healthConfig, healthLogger, 'publish:periodic');
    let lastAttemptState = null;
    const retryTimeline = [];
    const overallStartedAt = Date.now();
    let terminalFailureCategory = 'relay_publish_non_retryable';
    for (let attemptNumber = 1; attemptNumber <= maxAttempts; attemptNumber += 1) {
      const startedAtMs = Date.now();
      lastAttemptState = await publishOnce();
      const elapsedMs = Date.now() - startedAtMs;
      retryTimeline.push({
        publishAttempt: attemptNumber,
        successCount: lastAttemptState.successCount,
        relayAttemptedCount: lastAttemptState.attempted.size,
        elapsedMs,
      });

      if (lastAttemptState.successCount >= minSuccesses) {
        telemetryLogger(JSON.stringify({
          event: 'lock_publish_quorum_met',
          correlationId,
          attemptId,
          publishAttempt: attemptNumber,
          successCount: lastAttemptState.successCount,
          relayAttemptedCount: lastAttemptState.attempted.size,
          requiredSuccesses: minSuccesses,
          timeoutMs: publishTimeoutMs,
          retryTimeline,
          totalElapsedMs: Date.now() - overallStartedAt,
        }));
        console.error(
          `  Published to ${lastAttemptState.successCount}/${lastAttemptState.attempted.size} relays `
          + `(required=${minSuccesses}, timeout=${publishTimeoutMs}ms)`,
        );
        return event;
      }

      const hasTransientFailure = lastAttemptState.failures.some((failure) => isTransientPublishCategory(failure.category));
      const hasPermanentFailure = lastAttemptState.failures.some((failure) => !isTransientPublishCategory(failure.category));
      const canRetry = attemptNumber < maxAttempts && hasTransientFailure && !hasPermanentFailure;

      if (hasTransientFailure && !hasPermanentFailure && attemptNumber >= maxAttempts) {
        terminalFailureCategory = 'relay_publish_quorum_failure';
      } else if (hasPermanentFailure) {
        terminalFailureCategory = 'relay_publish_non_retryable';
      } else {
        terminalFailureCategory = 'relay_publish_quorum_failure';
      }

      if (!canRetry) {
        break;
      }

      const nextDelayMs = calculateBackoffDelayMs(attemptNumber, retryBaseDelayMs, retryCapDelayMs, randomFn);
      for (const failure of lastAttemptState.failures) {
        if (!isTransientPublishCategory(failure.category)) continue;
        telemetryLogger(JSON.stringify({
          event: 'lock_publish_retry',
          correlationId,
          attemptId,
          publishAttempt: attemptNumber,
          relayUrl: failure.relay,
          errorCategory: failure.category,
          elapsedMs,
          nextDelayMs,
        }));
      }

      await sleepFn(nextDelayMs);
    }

    const reasonDistribution = {};
    const failureLines = lastAttemptState.failures
      .map((result) => {
        reasonDistribution[result.category] = (reasonDistribution[result.category] || 0) + 1;
        telemetryLogger(JSON.stringify({
          event: 'lock_publish_failure',
          correlationId,
          attemptId,
          relayUrl: result.relay,
          phase: result.phase,
          reason: result.category,
          message: result.message,
        }));
        return `${result.relay} (${result.phase}, reason=${result.category}): ${result.message}`;
      });

    telemetryLogger(JSON.stringify({
      event: 'lock_publish_quorum_failed',
      correlationId,
      attemptId,
      errorCategory: terminalFailureCategory,
      successCount: lastAttemptState.successCount,
      relayAttemptedCount: lastAttemptState.attempted.size,
      requiredSuccesses: minSuccesses,
      timeoutMs: publishTimeoutMs,
      attempts: maxAttempts,
      reasonDistribution,
      retryTimeline,
      totalElapsedMs: Date.now() - overallStartedAt,
    }));

    maybeLogHealthSnapshot(allRelays, healthConfig, healthLogger, 'publish:failure', true);
    throw new Error(
      `Failed relay publish quorum in publish phase: ${lastAttemptState.successCount}/${lastAttemptState.attempted.size} successful `
      + `(required=${minSuccesses}, timeout=${publishTimeoutMs}ms, attempts=${maxAttempts}, attempt_id=${attemptId}, correlation_id=${correlationId}, error_category=${terminalFailureCategory}, total_retry_timeline_ms=${Date.now() - overallStartedAt})\n`
      + `  retry timeline: ${retryTimeline.map((item) => `#${item.publishAttempt}:${item.elapsedMs}ms`).join(', ')}\n`
      + `  ${failureLines.join('\n  ')}`,
    );
  } finally {
    pool.close(allRelays);
  }
}

export function _resetRelayHealthState() {
  relayHealthState.metricsByRelay.clear();
  relayHealthState.lastSnapshotAt = 0;
}
