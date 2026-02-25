import { createMemoryCache } from './cache.js';
import { ingestMemoryWindow } from './ingestor.js';
import { listPruneCandidates, selectPrunableMemories } from './pruner.js';
import { filterAndRankMemories, updateMemoryUsage } from './retriever.js';
import { startScheduler } from './scheduler.js';
import { getMemoryPruneMode, isMemoryIngestEnabled } from './feature-flags.js';
import fs from 'node:fs';
import path from 'node:path';
import util from 'node:util';
import { ensureDir } from '../../utils.mjs';

const MEMORY_FILE_PATH = path.join(process.cwd(), '.scheduler-memory', 'memory-store.json');
const debug = util.debuglog('torch-memory');

function loadMemoryStore() {
  try {
    if (fs.existsSync(MEMORY_FILE_PATH)) {
      const data = fs.readFileSync(MEMORY_FILE_PATH, 'utf8');
      const entries = JSON.parse(data);
      if (Array.isArray(entries)) {
        return new Map(entries);
      }
    }
  } catch (err) {
    console.error('Failed to load memory store:', err);
  }
  return new Map();
}

let currentSavePromise = null;
let pendingSavePromise = null;
let pendingSaveResolve = null;

async function performSave(store) {
  try {
    const dir = path.dirname(MEMORY_FILE_PATH);
    await fs.promises.mkdir(dir, { recursive: true });
    const entries = [...store.entries()];
    await fs.promises.writeFile(MEMORY_FILE_PATH, JSON.stringify(entries, null, 2), 'utf8');
  } catch (err) {
    console.error('Failed to save memory store:', err);
  } finally {
    currentSavePromise = null;
    if (pendingSavePromise) {
      const resolve = pendingSaveResolve;
      pendingSavePromise = null;
      pendingSaveResolve = null;
      currentSavePromise = performSave(store).then(() => resolve());
    }
  }
}

async function saveMemoryStore(store) {
  if (pendingSavePromise) {
    return pendingSavePromise;
  }

  if (currentSavePromise) {
    pendingSavePromise = new Promise((resolve) => {
      pendingSaveResolve = resolve;
    });
    return pendingSavePromise;
  }

  currentSavePromise = performSave(store);
  return currentSavePromise;
}

const memoryStore = loadMemoryStore();
const cache = createMemoryCache();

const memoryRepository = {
  async insertMemory(memory) {
    memoryStore.set(memory.id, memory);
    await saveMemoryStore(memoryStore);
    return memory;
  },
  async updateMemoryUsage(id, lastSeen = Date.now()) {
    const existing = memoryStore.get(id);
    if (!existing) return null;
    const updated = { ...existing, last_seen: lastSeen };
    memoryStore.set(id, updated);
    await saveMemoryStore(memoryStore);
    return updated;
  },
  async listPruneCandidates({ cutoff }) {
    return [...memoryStore.values()].filter((memory) => !memory.pinned && memory.last_seen < cutoff);
  },
  async markMerged(id, mergedInto) {
    const existing = memoryStore.get(id);
    if (!existing) return false;
    memoryStore.set(id, { ...existing, merged_into: mergedInto, last_seen: Date.now() });
    await saveMemoryStore(memoryStore);
    return true;
  },
  async setPinned(id, pinned) {
    const existing = memoryStore.get(id);
    if (!existing) return null;
    const updated = { ...existing, pinned, last_seen: Date.now() };
    memoryStore.set(id, updated);
    await saveMemoryStore(memoryStore);
    return updated;
  },
  async getMemoryById(id) {
    return memoryStore.get(id) ?? null;
  },
  async listMemories() {
    return [...memoryStore.values()];
  },
};

const memoryStatsState = {
  ingested: [],
  retrieved: [],
  pruned: [],
  archived: 0,
  deleted: 0,
};

const ESTIMATED_INDEX_BYTES_PER_RECORD = 512;

function toSafeTelemetryPayload(payload = {}) {
  const blockedFields = new Set(['content', 'summary', 'query', 'raw']);
  return Object.entries(payload).reduce((safe, [key, value]) => {
    if (blockedFields.has(key)) return safe;
    if (typeof value === 'string' && value.length > 300) {
      safe[key] = `${value.slice(0, 300)}…`;
      return safe;
    }
    safe[key] = value;
    return safe;
  }, {});
}

function buildTelemetryEmitter(options = {}) {
  if (typeof options.emitTelemetry === 'function') {
    return (event, payload) => options.emitTelemetry(event, toSafeTelemetryPayload(payload));
  }

  if (typeof options.telemetry?.emit === 'function') {
    return (event, payload) => options.telemetry.emit(event, toSafeTelemetryPayload(payload));
  }

  return (event, payload) => {
    debug('memory_telemetry', {
      event,
      payload: toSafeTelemetryPayload(payload),
      ts: Date.now(),
    });
  };
}

function emitMetric(options = {}, metric, payload) {
  if (typeof options.emitMetric === 'function') {
    options.emitMetric(metric, payload);
    return;
  }

  if (typeof options.metrics?.emit === 'function') {
    options.metrics.emit(metric, payload);
    return;
  }

  debug('memory_metric', { metric, payload, ts: Date.now() });
}

function applyMemoryFilters(memories, filters = {}) {
  const tags = Array.isArray(filters.tags)
    ? filters.tags.map((tag) => String(tag).trim()).filter(Boolean)
    : [];

  return memories.filter((memory) => {
    if (filters.agent_id && memory.agent_id !== filters.agent_id) return false;
    if (filters.type && memory.type !== filters.type) return false;
    if (typeof filters.pinned === 'boolean' && memory.pinned !== filters.pinned) return false;
    if (typeof filters.includeMerged === 'boolean' && !filters.includeMerged && memory.merged_into) return false;
    if (tags.length > 0) {
      const memoryTags = new Set(memory.tags);
      if (!tags.every((tag) => memoryTags.has(tag))) return false;
    }
    return true;
  });
}

function recordThroughput(samples, now) {
  samples.push(now);
  if (samples.length > 10_000) {
    samples.splice(0, samples.length - 10_000);
  }
}

/**
 * Ingests agent events and stores them as memory records.
 *
 * @param {import('./schema.js').MemoryEvent[]} events - Ordered list of raw events to persist.
 * @param {{ maxSummaryLength?: number, embedText?: (value: string) => Promise<number[]> | number[], repository?: typeof memoryRepository }} [options] - Optional ingest tuning.
 * @returns {Promise<import('./schema.js').MemoryRecord[]>} Stored memory records.
 */
export async function ingestEvents(events, options = {}) {
  const repository = options.repository ?? memoryRepository;
  const telemetry = buildTelemetryEmitter(options);
  if (!isMemoryIngestEnabled(options.agent_id, options.env)) {
    telemetry('memory:ingest_skipped', { reason: 'flag_disabled', agent_id: options.agent_id ?? null });
    return [];
  }
  const records = await ingestMemoryWindow({ events }, {
    ...options,
    repository,
    emitTelemetry: (event, payload) => {
      telemetry(event, payload);
      if (event === 'memory:ingested') {
        recordThroughput(memoryStatsState.ingested, Date.now());
        emitMetric(options, 'memory_ingested_total', { count: 1 });
      }
    },
  });
  cache.clear();
  return records;
}

/**
 * Retrieves top-k memories for an agent query.
 *
 * @param {{ agent_id: string, query?: string, tags?: string[], timeframe?: { from?: number, to?: number }, k?: number, repository?: typeof memoryRepository }} params - Retrieval filter and ranking inputs.
 * @returns {Promise<import('./schema.js').MemoryRecord[]>} Sorted list of relevant memories.
 */
export async function getRelevantMemories(params) {
  const {
    repository = memoryRepository,
    ranker = filterAndRankMemories,
    cache: cacheProvider = cache,
    ...queryParams
  } = params;
  const telemetry = buildTelemetryEmitter(params);
  const cacheKey = JSON.stringify(queryParams);
  const cached = cacheProvider.get(cacheKey);
  if (cached) {
    telemetry('memory:retrieved', {
      agent_id: queryParams.agent_id,
      result_count: cached.length,
      cache_hit: true,
      query_present: Boolean(queryParams.query),
      query_length: typeof queryParams.query === 'string' ? queryParams.query.length : 0,
      tags_count: Array.isArray(queryParams.tags) ? queryParams.tags.length : 0,
    });
    emitMetric(params, 'memory_retrieved_total', { count: cached.length, cache_hit: true });
    recordThroughput(memoryStatsState.retrieved, Date.now());
    return cached;
  }

  const source = typeof repository.listMemories === 'function'
    ? await repository.listMemories(queryParams)
    : [...memoryStore.values()];

  const ranked = await ranker(source, queryParams);
  await updateMemoryUsage(repository, ranked.map((memory) => memory.id));
  cacheProvider.set(cacheKey, ranked);

  telemetry('memory:retrieved', {
    agent_id: queryParams.agent_id,
    result_count: ranked.length,
    cache_hit: false,
    query_present: Boolean(queryParams.query),
    query_length: typeof queryParams.query === 'string' ? queryParams.query.length : 0,
    tags_count: Array.isArray(queryParams.tags) ? queryParams.tags.length : 0,
  });
  emitMetric(params, 'memory_retrieved_total', { count: ranked.length, cache_hit: false });
  recordThroughput(memoryStatsState.retrieved, Date.now());

  return ranked;
}

/**
 * Runs a memory pruning pass and removes unpinned stale records.
 *
 * @param {{ retentionMs?: number, now?: number, scheduleEveryMs?: number, repository?: typeof memoryRepository }} [options] - Prune configuration; if scheduleEveryMs is set, returns a scheduler handle.
 * @returns {Promise<{ pruned: import('./schema.js').MemoryRecord[], scheduler?: { stop: () => void } }>} Pruned records and optional scheduler handle.
 */
export async function runPruneCycle(options = {}) {
  const repository = options.repository ?? memoryRepository;
  const telemetry = buildTelemetryEmitter(options);
  const retentionMs = options.retentionMs ?? (1000 * 60 * 60 * 24 * 30);
  const pruneMode = options.pruneMode ?? getMemoryPruneMode(options.env);
  const dbCandidates = await listPruneCandidates(repository, {
    retentionMs,
    now: options.now,
  });

  const prunable = dbCandidates.length > 0
    ? dbCandidates
    : selectPrunableMemories([...memoryStore.values()], {
      retentionMs,
      now: options.now,
    });

  if (pruneMode === 'off') {
    telemetry('memory:prune_skipped', { reason: 'flag_disabled', retention_ms: retentionMs });
    return { pruned: [], mode: 'off' };
  }

  if (pruneMode === 'dry-run') {
    telemetry('memory:pruned', {
      pruned_count: prunable.length,
      retention_ms: retentionMs,
      dry_run: true,
    });
    emitMetric(options, 'memory_pruned_total', { count: 0, retention_ms: retentionMs, dry_run: true });
    return { pruned: [], candidates: prunable, mode: 'dry-run' };
  }

  for (const memory of prunable) {
    memoryStore.delete(memory.id);
  }

  if (prunable.length > 0) {
    await saveMemoryStore(memoryStore);
  }

  memoryStatsState.deleted += prunable.length;
  recordThroughput(memoryStatsState.pruned, Date.now());
  telemetry('memory:pruned', {
    pruned_count: prunable.length,
    retention_ms: retentionMs,
  });
  emitMetric(options, 'memory_pruned_total', { count: prunable.length, retention_ms: retentionMs });

  cache.clear();

  const result = { pruned: prunable };
  if (Number.isFinite(options.scheduleEveryMs) && options.scheduleEveryMs > 0) {
    result.scheduler = startScheduler(() => runPruneCycle({ retentionMs, repository, env: options.env, pruneMode: options.pruneMode }), {
      intervalMs: options.scheduleEveryMs,
    });
  }

  return result;
}

/**
 * Pins a memory to prevent pruning and boost retrieval ranking.
 *
 * @param {string} id - Memory record identifier.
 * @returns {Promise<import('./schema.js').MemoryRecord | null>} Updated memory record or null when not found.
 */
export async function pinMemory(id, options = {}) {
  const repository = options.repository ?? memoryRepository;
  const updated = await repository.setPinned(id, true);
  cache.clear();
  return updated;
}

/**
 * Removes a pin from a memory so it can be pruned normally.
 *
 * @param {string} id - Memory record identifier.
 * @returns {Promise<import('./schema.js').MemoryRecord | null>} Updated memory record or null when not found.
 */
export async function unpinMemory(id, options = {}) {
  const repository = options.repository ?? memoryRepository;
  const updated = await repository.setPinned(id, false);
  cache.clear();
  return updated;
}

/**
 * Marks one memory as merged into another.
 *
 * @param {string} id
 * @param {string} mergedInto
 */
export async function markMemoryMerged(id, mergedInto, options = {}) {
  const repository = options.repository ?? memoryRepository;
  const merged = await repository.markMerged(id, mergedInto);
  cache.clear();
  return merged;
}

export async function listMemories(filters = {}, options = {}) {
  const repository = options.repository ?? memoryRepository;
  const source = typeof repository.listMemories === 'function'
    ? await repository.listMemories(filters)
    : [...memoryStore.values()];

  const filtered = applyMemoryFilters(source, filters)
    .sort((left, right) => right.last_seen - left.last_seen);

  const offset = Number.isFinite(filters.offset) ? Math.max(0, Number(filters.offset)) : 0;
  const limit = Number.isFinite(filters.limit)
    ? Math.max(1, Math.floor(Number(filters.limit)))
    : filtered.length;

  return filtered.slice(offset, offset + limit);
}

export async function inspectMemory(id, options = {}) {
  const repository = options.repository ?? memoryRepository;
  if (typeof repository.getMemoryById === 'function') {
    return repository.getMemoryById(id);
  }
  return memoryStore.get(id) ?? null;
}

export async function triggerPruneDryRun(options = {}) {
  const repository = options.repository ?? memoryRepository;
  const retentionMs = options.retentionMs ?? (1000 * 60 * 60 * 24 * 30);
  const dbCandidates = await listPruneCandidates(repository, {
    retentionMs,
    now: options.now,
  });

  const candidates = dbCandidates.length > 0
    ? dbCandidates
    : selectPrunableMemories(await listMemories({}, { repository }), {
      retentionMs,
      now: options.now,
    });

  return {
    dryRun: true,
    retentionMs,
    candidateCount: candidates.length,
    candidates: candidates.map((memory) => ({
      id: memory.id,
      agent_id: memory.agent_id,
      type: memory.type,
      pinned: memory.pinned,
      last_seen: memory.last_seen,
      merged_into: memory.merged_into,
    })),
  };
}

export async function memoryStats(options = {}) {
  const repository = options.repository ?? memoryRepository;
  const now = options.now ?? Date.now();
  const windowMs = Number.isFinite(options.windowMs) ? Math.max(1, Number(options.windowMs)) : (60 * 60 * 1000);
  const memories = await listMemories({}, { repository });

  const countsByType = memories.reduce((acc, memory) => {
    acc[memory.type] = (acc[memory.type] ?? 0) + 1;
    return acc;
  }, {});

  const archivedCount = memories.filter((memory) => Boolean(memory.merged_into)).length;
  const deletedRate = memoryStatsState.deleted / Math.max(1, memoryStatsState.ingested.length);
  const archivedRate = archivedCount / Math.max(1, memories.length);

  const ingestedInWindow = memoryStatsState.ingested.filter((timestamp) => timestamp >= (now - windowMs)).length;
  const ingestThroughputPerMinute = ingestedInWindow / Math.max(1, (windowMs / 60_000));

  return {
    countsByType,
    totals: {
      total: memories.length,
      pinned: memories.filter((memory) => memory.pinned).length,
      archived: archivedCount,
      deletedObserved: memoryStatsState.deleted,
    },
    rates: {
      archivedRate,
      deletedRate,
    },
    indexSizeEstimateBytes: memories.length * ESTIMATED_INDEX_BYTES_PER_RECORD,
    ingestThroughputPerMinute,
  };
}
