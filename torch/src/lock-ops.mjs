import { randomInt, randomUUID } from 'node:crypto';
import { SimplePool } from 'nostr-tools/pool';
import {
  getQueryTimeoutMs,
  getPublishTimeoutMs,
  getMinSuccessfulRelayPublishes,
  getRelayFallbacks,
  getMinActiveRelayPool,
} from './torch-config.mjs';
import {
  KIND_APP_DATA,
  DEFAULT_RETRY_ATTEMPTS,
  DEFAULT_RETRY_BASE_DELAY_MS,
  DEFAULT_RETRY_CAP_DELAY_MS,
  DEFAULT_ROLLING_WINDOW_SIZE,
  DEFAULT_FAILURE_THRESHOLD,
  DEFAULT_QUARANTINE_COOLDOWN_MS,
  DEFAULT_MAX_QUARANTINE_COOLDOWN_MS,
  DEFAULT_SNAPSHOT_INTERVAL_MS,
} from './constants.mjs';

function nowUnix() {
  return Math.floor(Date.now() / 1000);
}

/**
 * Parses a raw Nostr event into a structured lock object.
 * Extracts metadata from tags (d-tag, expiration) and parses the JSON content.
 *
 * @param {Object} event - The raw Nostr event object.
 * @returns {Object} A structured lock object containing event metadata and parsed content.
 */
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

const PUBLISH_ERROR_CODES = {
  TIMEOUT: 'publish_timeout',
  DNS: 'dns_resolution',
  TCP: 'tcp_connect_timeout',
  TLS: 'tls_handshake',
  WEBSOCKET: 'websocket_open_failure',
  NETWORK: 'network_timeout',
  CONNECTION_RESET: 'connection_reset',
  RELAY_UNAVAILABLE: 'relay_unavailable',
  PERMANENT: 'permanent_validation_error',
};

const PUBLISH_FAILURE_CATEGORIES = {
  QUORUM_FAILURE: 'relay_publish_quorum_failure',
  NON_RETRYABLE: 'relay_publish_non_retryable',
};

/**
 * Classifies a raw error message into a standardized publication error code.
 * Used to determine if a failure is transient (retryable) or permanent.
 *
 * @param {string|Error} message - The error message or object to classify.
 * @returns {string} One of the PUBLISH_ERROR_CODES constants.
 */
function classifyPublishError(message) {
  const normalized = String(message || '').toLowerCase();
  if (normalized.includes('publish timed out after') || normalized.includes('publish timeout')) {
    return PUBLISH_ERROR_CODES.TIMEOUT;
  }
  if (
    normalized.includes('enotfound')
    || normalized.includes('eai_again')
    || normalized.includes('getaddrinfo')
    || (normalized.includes('dns') && normalized.includes('websocket'))
  ) {
    return PUBLISH_ERROR_CODES.DNS;
  }
  if (
    normalized.includes('connect etimedout')
    || normalized.includes('tcp connect timed out')
    || normalized.includes('connect timeout')
  ) {
    return PUBLISH_ERROR_CODES.TCP;
  }
  if (
    normalized.includes('tls')
    || normalized.includes('ssl')
    || normalized.includes('certificate')
    || normalized.includes('handshake')
  ) {
    return PUBLISH_ERROR_CODES.TLS;
  }
  if (
    normalized.includes('websocket')
    || normalized.includes('bad response')
    || normalized.includes('unexpected server response')
  ) {
    return PUBLISH_ERROR_CODES.WEBSOCKET;
  }
  if (normalized.includes('timed out') || normalized.includes('timeout') || normalized.includes('etimedout')) {
    return PUBLISH_ERROR_CODES.NETWORK;
  }
  if (normalized.includes('econnreset') || normalized.includes('connection reset') || normalized.includes('socket hang up')) {
    return PUBLISH_ERROR_CODES.CONNECTION_RESET;
  }
  if (
    normalized.includes('unavailable')
    || normalized.includes('offline')
    || normalized.includes('econnrefused')
    || normalized.includes('connection refused')
    || normalized.includes('enotfound')
    || normalized.includes('503')
  ) {
    return PUBLISH_ERROR_CODES.RELAY_UNAVAILABLE;
  }
  return PUBLISH_ERROR_CODES.PERMANENT;
}

function isTransientPublishCategory(category) {
  return [
    PUBLISH_ERROR_CODES.TIMEOUT,
    PUBLISH_ERROR_CODES.DNS,
    PUBLISH_ERROR_CODES.TCP,
    PUBLISH_ERROR_CODES.TLS,
    PUBLISH_ERROR_CODES.WEBSOCKET,
    PUBLISH_ERROR_CODES.NETWORK,
    PUBLISH_ERROR_CODES.CONNECTION_RESET,
    PUBLISH_ERROR_CODES.RELAY_UNAVAILABLE,
  ].includes(category);
}

const MAX_RANDOM = 281474976710655; // 2**48 - 1

function secureRandom() {
  return randomInt(0, MAX_RANDOM) / MAX_RANDOM;
}

function calculateBackoffDelayMs(attemptNumber, baseMs, capMs, randomFn = secureRandom) {
  const maxDelay = Math.min(capMs, baseMs * (2 ** Math.max(0, attemptNumber - 1)));
  return Math.floor(randomFn() * maxDelay);
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

/**
 * Manages health metrics, scoring, and prioritization for Nostr relays.
 * Tracks success rates, timeouts, and latency to optimize relay selection.
 * Implements a quarantine mechanism for failing relays.
 */
export class RelayHealthManager {
  constructor() {
    this.metricsByRelay = new Map();
    this.lastSnapshotAt = 0;
    this._metricsVersion = 0;
    this._sortedCache = null;
  }

  ensureMetrics(relay, config) {
    let metrics = this.metricsByRelay.get(relay);
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
      this.metricsByRelay.set(relay, metrics);
      this._metricsVersion += 1;
    }
    return metrics;
  }

  /**
   * Ranks a list of relays based on their health scores.
   * Utilizes a cached sort order to avoid re-sorting on every call if metrics haven't changed.
   *
   * @param {string[]} relays - List of relay URLs to rank.
   * @param {Object} config - Health configuration.
   * @param {number} [nowMs] - Current timestamp.
   * @returns {Array} List of ranked relay entries with scores and summaries.
   */
  rankRelays(relays, config, nowMs = Date.now()) {
    for (const relay of relays) {
      this.ensureMetrics(relay, config);
    }

    // Check if the cached sort order is still valid
    if (
      !this._sortedCache
      || this._sortedCache.version !== this._metricsVersion
      || nowMs >= this._sortedCache.validUntil
    ) {
      let minQuarantineUntil = Infinity;
      const entries = [];

      // Re-evaluate scores for all tracked relays
      for (const metrics of this.metricsByRelay.values()) {
        const summary = summarizeRelayMetrics(metrics, nowMs);
        const score = computeRelayScore(summary);
        if (metrics.quarantineUntil > nowMs && metrics.quarantineUntil < minQuarantineUntil) {
          minQuarantineUntil = metrics.quarantineUntil;
        }
        entries.push({
          relay: metrics.relay,
          summary,
          score,
          metrics,
        });
      }

      // Sort by score (desc), then quarantine status, then latency (asc), then name
      const comparator = (a, b) => {
        if (b.score !== a.score) return b.score - a.score;
        if (a.summary.quarantined !== b.summary.quarantined) return a.summary.quarantined ? 1 : -1;
        if (a.summary.averageLatencyMs !== b.summary.averageLatencyMs) {
          if (a.summary.averageLatencyMs === null) return 1;
          if (b.summary.averageLatencyMs === null) return -1;
          return a.summary.averageLatencyMs - b.summary.averageLatencyMs;
        }
        return a.relay.localeCompare(b.relay);
      };
      entries.sort(comparator);

      this._sortedCache = {
        version: this._metricsVersion,
        validUntil: minQuarantineUntil,
        entries,
        byRelay: new Map(entries.map((e) => [e.relay, e])),
        comparator,
      };
    }

    // Optimization: if requesting a small subset of total known relays,
    // look them up directly instead of filtering the entire list.
    // Threshold: if requested set is smaller than 50% of cached entries.
    if (relays.length > 0 && relays.length * 2 < this._sortedCache.entries.length) {
      const subset = [];
      for (const relay of relays) {
        const entry = this._sortedCache.byRelay.get(relay);
        if (entry) {
          subset.push(entry);
        }
      }
      // Re-sort the subset to maintain ranking order
      subset.sort(this._sortedCache.comparator);

      return subset.map((entry) => {
        const quarantineRemainingMs = entry.metrics.quarantineUntil > nowMs
          ? entry.metrics.quarantineUntil - nowMs
          : 0;
        return {
          relay: entry.relay,
          score: entry.score,
          summary: {
            ...entry.summary,
            quarantineRemainingMs,
          },
        };
      });
    }

    const requestedSet = new Set(relays);
    return this._sortedCache.entries
      .filter((entry) => requestedSet.has(entry.relay))
      .map((entry) => {
        const quarantineRemainingMs = entry.metrics.quarantineUntil > nowMs
          ? entry.metrics.quarantineUntil - nowMs
          : 0;
        return {
          relay: entry.relay,
          score: entry.score,
          summary: {
            ...entry.summary,
            quarantineRemainingMs,
          },
        };
      });
  }

  /**
   * Selects a subset of relays for immediate use, prioritizing healthy ones.
   * May include quarantined relays if the number of healthy relays is below `minActiveRelayPool`.
   *
   * @param {string[]} relays - Candidate relays.
   * @param {Object} config - Health configuration.
   * @param {number} [nowMs] - Current timestamp.
   * @returns {Object} An object containing `prioritized` (list of selected relay URLs) and `ranked` (full ranking details).
   */
  prioritizeRelays(relays, config, nowMs = Date.now()) {
    const minActive = Math.max(1, Math.min(config.minActiveRelayPool, relays.length || 1));
    const ranked = this.rankRelays([...new Set(relays)], config, nowMs);
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

  /**
   * Updates health metrics for a relay based on the outcome of an operation.
   *
   * @param {string} relay - The relay URL.
   * @param {boolean} success - Whether the operation succeeded.
   * @param {string} errorMessage - Error message if failed.
   * @param {number} latencyMs - Duration of the operation.
   * @param {Object} config - Health configuration.
   * @param {number} [nowMs] - Current timestamp.
   */
  recordOutcome(relay, success, errorMessage, latencyMs, config, nowMs = Date.now()) {
    const metrics = this.ensureMetrics(relay, config);
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
    this._metricsVersion += 1;
  }

  collectSnapshot(relays, config, nowMs = Date.now()) {
    const uniqueRelays = [...new Set(relays)];
    return this.rankRelays(uniqueRelays, config, nowMs).map((entry) => ({
      relay: entry.relay,
      score: Number(entry.score.toFixed(4)),
      ...entry.summary,
    }));
  }

  maybeLogSnapshot(relays, config, logger, reason, force = false, nowMs = Date.now()) {
    const intervalReached = nowMs - this.lastSnapshotAt >= config.snapshotIntervalMs;
    if (!force && !intervalReached) return;
    this.lastSnapshotAt = nowMs;
    logger(JSON.stringify({
      event: 'relay_health_snapshot',
      reason,
      relays: this.collectSnapshot(relays, config, nowMs),
    }));
  }

  reset() {
    this.metricsByRelay.clear();
    this.lastSnapshotAt = 0;
    this._metricsVersion = 0;
    this._sortedCache = null;
  }
}

export const defaultHealthManager = new RelayHealthManager();

function buildRelayHealthConfig(deps) {
  return {
    rollingWindowSize: deps.rollingWindowSize ?? DEFAULT_ROLLING_WINDOW_SIZE,
    failureThreshold: deps.failureThreshold ?? DEFAULT_FAILURE_THRESHOLD,
    quarantineCooldownMs: deps.quarantineCooldownMs ?? DEFAULT_QUARANTINE_COOLDOWN_MS,
    maxQuarantineCooldownMs: deps.maxQuarantineCooldownMs ?? DEFAULT_MAX_QUARANTINE_COOLDOWN_MS,
    snapshotIntervalMs: deps.snapshotIntervalMs ?? DEFAULT_SNAPSHOT_INTERVAL_MS,
    minActiveRelayPool: Math.max(1, deps.minActiveRelayPool ?? 1),
  };
}

function mergeRelayList(primaryRelays, fallbackRelays) {
  return [...new Set([...primaryRelays, ...fallbackRelays])];
}

/**
 * Queries relays for active lock events matching the criteria.
 * Uses a tiered approach: tries primary relays first, then falls back to others if needed.
 *
 * @param {string[]} relays - List of primary relay URLs.
 * @param {string} cadence - The cadence (e.g., 'daily', 'weekly').
 * @param {string} dateStr - The date string (e.g., '2023-10-27').
 * @param {string} namespace - The lock namespace (e.g., 'torch').
 * @param {Object} [deps] - Dependencies and configuration overrides.
 * @returns {Promise<Array>} A promise resolving to an array of active lock objects.
 * @throws {Error} If the query fails on all attempted relays (primary + fallback).
 */
export async function queryLocks(relays, cadence, dateStr, namespace, deps = {}) {
  const {
    poolFactory = () => new SimplePool(),
    getQueryTimeoutMsFn = getQueryTimeoutMs,
    getRelayFallbacksFn = getRelayFallbacks,
    getMinActiveRelayPoolFn = getMinActiveRelayPool,
    errorLogger = console.error,
    healthLogger = console.error,
    healthManager = defaultHealthManager,
  } = deps;

  const pool = poolFactory();
  const tagFilter = `${namespace}-lock-${cadence}-${dateStr}`;
  const queryTimeoutMs = await getQueryTimeoutMsFn();
  const fallbackRelays = (await getRelayFallbacksFn()).filter((relay) => !relays.includes(relay));
  const healthConfig = buildRelayHealthConfig({
    ...deps,
    minActiveRelayPool: await getMinActiveRelayPoolFn(),
  });

  const runQuery = async (relaySet, phase) => {
    const { prioritized } = healthManager.prioritizeRelays(relaySet, healthConfig);
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
        healthManager.recordOutcome(relay, true, null, elapsedMs, healthConfig);
      }
      return filterActiveLocks(events.map(parseLockEvent));
    } catch (err) {
      const elapsedMs = Date.now() - startedAtMs;
      const message = err instanceof Error ? err.message : String(err);
      for (const relay of prioritized) {
        healthManager.recordOutcome(relay, false, message, elapsedMs, healthConfig);
      }
      throw new Error(
        `[${phase}] Relay query failed (timeout=${queryTimeoutMs}ms, relays=${relayListLabel(prioritized)}): ${message}`,
        { cause: err },
      );
    }
  };

  const allRelays = mergeRelayList(relays, fallbackRelays);

  try {
    healthManager.maybeLogSnapshot(allRelays, healthConfig, healthLogger, 'query:periodic');
    try {
      return await runQuery(relays, 'query:primary');
    } catch (primaryErr) {
      if (!fallbackRelays.length) {
        healthManager.maybeLogSnapshot(allRelays, healthConfig, healthLogger, 'query:failure', true);
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

/**
 * Orchestrates the publication of a lock event to multiple relays.
 * Handles retries, fallback relays, and health-based relay prioritization.
 *
 * Cycle:
 * 1. Attempt to publish to primary relays.
 * 2. If quorum not met, attempt fallback relays.
 * 3. If still failing, retry with backoff (if errors are transient).
 * 4. Report final success or failure.
 */
export class LockPublisher {
  /**
   * @param {string[]} relays - Target primary relays.
   * @param {Object} event - The lock event to publish.
   * @param {Object} [deps] - Dependencies and configuration.
   */
  constructor(relays, event, deps = {}) {
    this.relays = relays;
    this.event = event;
    this.deps = deps;
    this.pool = null;
    this.healthConfig = null;
    this.allRelays = [];
    this.fallbackRelays = [];
    this.publishTimeoutMs = 0;
    this.minSuccesses = 0;
    this.minActiveRelayPool = 0;
    this.maxAttempts = 0;
    this.retryBaseDelayMs = 0;
    this.retryCapDelayMs = 0;
    this.sleepFn = null;
    this.randomFn = null;
    this.telemetryLogger = null;
    this.healthLogger = null;
    this.healthManager = null;
    this.correlationId = null;
    this.attemptId = null;
  }

  /**
   * Executes the publication process with retries.
   *
   * @returns {Promise<Object>} The published event if successful.
   * @throws {Error} If publication quorum is not met after all attempts.
   */
  async publish() {
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
      healthManager = defaultHealthManager,
    } = this.deps;

    this.healthManager = healthManager;
    this.pool = poolFactory();
    this.publishTimeoutMs = this.deps.resolvedConfig?.publishTimeoutMs;
    this.minSuccesses = this.deps.resolvedConfig?.minSuccesses;
    this.fallbackRelays = (this.deps.resolvedConfig?.fallbackRelays || []).filter((relay) => !this.relays.includes(relay));
    this.maxAttempts = Math.max(1, Math.floor(retryAttempts));
    this.healthConfig = buildRelayHealthConfig({
      ...this.deps,
      minActiveRelayPool: this.deps.resolvedConfig?.minActiveRelayPool,
    });

    this.retryBaseDelayMs = retryBaseDelayMs;
    this.retryCapDelayMs = retryCapDelayMs;
    this.sleepFn = sleepFn;
    this.randomFn = randomFn;
    this.telemetryLogger = telemetryLogger;
    this.healthLogger = healthLogger;
    this.healthManager = healthManager;
    this.correlationId = diagnostics.correlationId || randomUUID();
    this.attemptId = diagnostics.attemptId || randomUUID();

    this.allRelays = mergeRelayList(this.relays, this.fallbackRelays);

    try {
      this.healthManager.maybeLogSnapshot(this.allRelays, this.healthConfig, this.healthLogger, 'publish:periodic');
      let lastAttemptState = null;
      const retryTimeline = [];
      const overallStartedAt = Date.now();
      let terminalFailureCategory = PUBLISH_FAILURE_CATEGORIES.NON_RETRYABLE;

      // Retry loop: attempts publication until success or max attempts reached
      for (let attemptNumber = 1; attemptNumber <= this.maxAttempts; attemptNumber += 1) {
        const startedAtMs = Date.now();
        lastAttemptState = await this.executePublishCycle();
        const elapsedMs = Date.now() - startedAtMs;
        retryTimeline.push({
          publishAttempt: attemptNumber,
          successCount: lastAttemptState.successCount,
          relayAttemptedCount: lastAttemptState.attempted.size,
          elapsedMs,
        });

        if (lastAttemptState.successCount >= this.minSuccesses) {
          this.logSuccess(attemptNumber, lastAttemptState, retryTimeline, overallStartedAt);
          return this.event;
        }

        const { hasTransientFailure, hasPermanentFailure } = this.analyzeFailures(lastAttemptState.failures);
        const canRetry = attemptNumber < this.maxAttempts && hasTransientFailure && !hasPermanentFailure;

        terminalFailureCategory = this.determineFailureCategory(hasTransientFailure, hasPermanentFailure, attemptNumber);

        if (!canRetry) {
          break;
        }

        const nextDelayMs = calculateBackoffDelayMs(attemptNumber, this.retryBaseDelayMs, this.retryCapDelayMs, this.randomFn);
        this.logRetry(attemptNumber, lastAttemptState.failures, elapsedMs, nextDelayMs);
        await this.sleepFn(nextDelayMs);
      }

      this.handleFinalFailure(lastAttemptState, terminalFailureCategory, retryTimeline, overallStartedAt);
    } finally {
      this.pool.close(this.allRelays);
    }
  }

  async executePublishCycle() {
    const attempted = new Set();
    const publishResults = [];

    await this.attemptPhase(this.relays, 'publish:primary', attempted, publishResults);

    let successCount = publishResults.filter((result) => result.success).length;
    if (successCount < this.minSuccesses && this.fallbackRelays.length > 0) {
      await this.attemptPhase(this.fallbackRelays, 'publish:fallback', attempted, publishResults);
      successCount = publishResults.filter((result) => result.success).length;
    }

    const failures = publishResults
      .filter((result) => !result.success)
      .map((result) => ({
        ...result,
        category: classifyPublishError(result.message),
      }));

    return { attempted, publishResults, successCount, failures };
  }

  async attemptPhase(phaseRelays, phaseName, attempted, publishResults) {
    if (!phaseRelays.length) return;
    const { prioritized } = this.healthManager.prioritizeRelays(phaseRelays, this.healthConfig);
    if (!prioritized.length) return;

    console.error(`[${phaseName}] Publishing to ${prioritized.length} relays (${prioritized.join(', ')})...`);

    const startedAtMs = Date.now();
    for (const relay of prioritized) {
      attempted.add(relay);
    }
    const phaseResults = await publishToRelays(this.pool, prioritized, this.event, this.publishTimeoutMs, phaseName);
    const elapsedMs = Date.now() - startedAtMs;
    for (const result of phaseResults) {
      result.latencyMs = elapsedMs;
      this.healthManager.recordOutcome(result.relay, result.success, result.message, elapsedMs, this.healthConfig);
    }
    publishResults.push(...phaseResults);
  }

  analyzeFailures(failures) {
    const hasTransientFailure = failures.some((failure) => isTransientPublishCategory(failure.category));
    const hasPermanentFailure = failures.some((failure) => !isTransientPublishCategory(failure.category));
    return { hasTransientFailure, hasPermanentFailure };
  }

  determineFailureCategory(hasTransientFailure, hasPermanentFailure, attemptNumber) {
    if (hasTransientFailure && !hasPermanentFailure && attemptNumber >= this.maxAttempts) {
      return PUBLISH_FAILURE_CATEGORIES.QUORUM_FAILURE;
    } else if (hasPermanentFailure) {
      return PUBLISH_FAILURE_CATEGORIES.NON_RETRYABLE;
    } else {
      return PUBLISH_FAILURE_CATEGORIES.QUORUM_FAILURE;
    }
  }

  logSuccess(attemptNumber, lastAttemptState, retryTimeline, overallStartedAt) {
    this.telemetryLogger(JSON.stringify({
      event: 'lock_publish_quorum_met',
      correlationId: this.correlationId,
      attemptId: this.attemptId,
      publishAttempt: attemptNumber,
      successCount: lastAttemptState.successCount,
      relayAttemptedCount: lastAttemptState.attempted.size,
      requiredSuccesses: this.minSuccesses,
      timeoutMs: this.publishTimeoutMs,
      retryTimeline,
      totalElapsedMs: Date.now() - overallStartedAt,
    }));
    console.error(
      `  Published to ${lastAttemptState.successCount}/${lastAttemptState.attempted.size} relays `
      + `(required=${this.minSuccesses}, timeout=${this.publishTimeoutMs}ms)`,
    );
  }

  logRetry(attemptNumber, failures, elapsedMs, nextDelayMs) {
    for (const failure of failures) {
      if (!isTransientPublishCategory(failure.category)) continue;
      this.telemetryLogger(JSON.stringify({
        event: 'lock_publish_retry',
        correlationId: this.correlationId,
        attemptId: this.attemptId,
        publishAttempt: attemptNumber,
        relayUrl: failure.relay,
        errorCategory: failure.category,
        elapsedMs,
        nextDelayMs,
      }));
    }
  }

  handleFinalFailure(lastAttemptState, terminalFailureCategory, retryTimeline, overallStartedAt) {
    const reasonDistribution = {};
    const failureLines = lastAttemptState.failures
      .map((result) => {
        reasonDistribution[result.category] = (reasonDistribution[result.category] || 0) + 1;
        this.telemetryLogger(JSON.stringify({
          event: 'lock_publish_failure',
          correlationId: this.correlationId,
          attemptId: this.attemptId,
          relayUrl: result.relay,
          phase: result.phase,
          reason: result.category,
          message: result.message,
        }));
        return `${result.relay} (${result.phase}, reason=${result.category}): ${result.message}`;
      });

    this.telemetryLogger(JSON.stringify({
      event: 'lock_publish_quorum_failed',
      correlationId: this.correlationId,
      attemptId: this.attemptId,
      errorCategory: terminalFailureCategory,
      successCount: lastAttemptState.successCount,
      relayAttemptedCount: lastAttemptState.attempted.size,
      requiredSuccesses: this.minSuccesses,
      timeoutMs: this.publishTimeoutMs,
      attempts: this.maxAttempts,
      reasonDistribution,
      retryTimeline,
      totalElapsedMs: Date.now() - overallStartedAt,
    }));

    this.healthManager.maybeLogSnapshot(this.allRelays, this.healthConfig, this.healthLogger, 'publish:failure', true);
    throw new Error(
      `Failed relay publish quorum in publish phase: ${lastAttemptState.successCount}/${lastAttemptState.attempted.size} successful `
      + `(required=${this.minSuccesses}, timeout=${this.publishTimeoutMs}ms, attempts=${this.maxAttempts}, attempt_id=${this.attemptId}, correlation_id=${this.correlationId}, error_category=${terminalFailureCategory}, total_retry_timeline_ms=${Date.now() - overallStartedAt})\n`
      + `  retry timeline: ${retryTimeline.map((item) => `#${item.publishAttempt}:${item.elapsedMs}ms`).join(', ')}\n`
      + `  ${failureLines.join('\n  ')}`,
    );
  }
}

/**
 * High-level function to publish a lock event.
 * Initializes a LockPublisher and triggers the publication process.
 *
 * @param {string[]} relays - Target relays.
 * @param {Object} event - Lock event to publish.
 * @param {Object} [deps] - Dependencies.
 * @returns {Promise<Object>} The published event.
 */
export async function publishLock(relays, event, deps = {}) {
  const {
    getPublishTimeoutMsFn = getPublishTimeoutMs,
    getMinSuccessfulRelayPublishesFn = getMinSuccessfulRelayPublishes,
    getRelayFallbacksFn = getRelayFallbacks,
    getMinActiveRelayPoolFn = getMinActiveRelayPool,
  } = deps;

  const [publishTimeoutMs, minSuccesses, fallbackRelays, minActiveRelayPool] = await Promise.all([
    getPublishTimeoutMsFn(),
    getMinSuccessfulRelayPublishesFn(),
    getRelayFallbacksFn(),
    getMinActiveRelayPoolFn(),
  ]);

  return new LockPublisher(relays, event, {
    ...deps,
    resolvedConfig: {
      publishTimeoutMs,
      minSuccesses,
      fallbackRelays,
      minActiveRelayPool,
    },
  }).publish();
}

export function _resetRelayHealthState() {
  defaultHealthManager.reset();
}

export const _secureRandom = secureRandom;
