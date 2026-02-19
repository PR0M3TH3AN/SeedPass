const DEFAULT_WEIGHTS = {
  w_sim: 0.6,
  w_imp: 0.25,
  w_rec: 0.15,
  pinBoost: 0.15,
};

const DEFAULT_RECENCY_HALF_LIFE_MS = 1000 * 60 * 60 * 24 * 7;

function cosineSimilarity(left = [], right = []) {
  const size = Math.max(left.length, right.length);
  let dot = 0;
  let leftNorm = 0;
  let rightNorm = 0;

  for (let index = 0; index < size; index += 1) {
    const leftValue = Number(left[index] ?? 0);
    const rightValue = Number(right[index] ?? 0);
    dot += leftValue * rightValue;
    leftNorm += leftValue ** 2;
    rightNorm += rightValue ** 2;
  }

  if (leftNorm === 0 || rightNorm === 0) return 0;
  return dot / (Math.sqrt(leftNorm) * Math.sqrt(rightNorm));
}

function computeRecencyDecay(timestamp, now, halfLifeMs) {
  if (!Number.isFinite(timestamp) || !Number.isFinite(now) || halfLifeMs <= 0) return 0;
  const age = Math.max(0, now - timestamp);
  return Math.exp(-(age / halfLifeMs));
}

function escapeRegExp(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function textMatchSimilarity(queryTerms, queryRegexes, memory) {
  if (!queryTerms || queryTerms.length === 0) return 0;

  let matchedTerms = 0;
  for (const regex of queryRegexes) {
    if (regex.test(memory.summary) || regex.test(memory.content)) {
      matchedTerms++;
    }
  }

  return matchedTerms / queryTerms.length;
}

/**
 * @param {import('./schema.js').MemoryRecord} memory
 * @param {{ tags: string[], timeframe?: { from?: number, to?: number }, pinnedPreference?: 'prefer' | 'only' | 'exclude' }} params
 */
function matchesMetadataFilters(memory, params) {
  const inTimeframe = !params.timeframe
    || ((params.timeframe.from == null || memory.created_at >= params.timeframe.from)
      && (params.timeframe.to == null || memory.created_at <= params.timeframe.to));

  if (!inTimeframe) return false;

  if (params.tags.length > 0) {
    const memoryTags = new Set(memory.tags);
    const matchesAllTags = params.tags.every((tag) => memoryTags.has(tag));
    if (!matchesAllTags) return false;
  }

  if (params.pinnedPreference === 'only' && !memory.pinned) return false;
  if (params.pinnedPreference === 'exclude' && memory.pinned) return false;

  return true;
}

/**
 * @param {import('./schema.js').MemoryRecord[]} memories
 * @param {{ query: string, agent_id: string, k: number, vectorAdapter?: { embedText: (text: string) => Promise<number[]> | number[], queryVector: (input: { vector: number[], k?: number, filter?: Record<string, unknown> }) => Promise<Array<{ id: string, score: number }>> | Array<{ id: string, score: number }> }, embedText?: (value: string) => Promise<number[]> | number[] }} params
 */
async function buildSimilarityIndex(memories, params) {
  const similarityById = new Map();
  const normalizedQuery = params.query.trim();

  if (!normalizedQuery) {
    return similarityById;
  }

  if (params.vectorAdapter && typeof params.vectorAdapter.queryVector === 'function') {
    const queryVector = typeof params.embedText === 'function'
      ? await params.embedText(normalizedQuery)
      : await params.vectorAdapter.embedText(normalizedQuery);

    const vectorHits = await params.vectorAdapter.queryVector({
      vector: queryVector,
      k: Math.max(params.k * 4, memories.length),
      filter: { agent_id: params.agent_id },
    });

    for (const hit of vectorHits) {
      if (typeof hit.id === 'string' && Number.isFinite(hit.score)) {
        similarityById.set(hit.id, Math.max(0, Number(hit.score)));
      }
    }

    if (similarityById.size > 0) {
      return similarityById;
    }
  }

  const queryTerms = normalizedQuery.toLowerCase().split(/\s+/).filter(Boolean);
  const queryRegexes = queryTerms.map((t) => new RegExp(escapeRegExp(t), 'i'));

  for (const memory of memories) {
    const lexicalScore = textMatchSimilarity(queryTerms, queryRegexes, memory);
    if (lexicalScore > 0) {
      similarityById.set(memory.id, lexicalScore);
    }
  }

  return similarityById;
}

/**
 * @param {import('./schema.js').MemoryRecord[]} memories
 * @param {{ agent_id: string, query?: string, tags?: string[], timeframe?: { from?: number, to?: number }, k?: number, pinnedPreference?: 'prefer' | 'only' | 'exclude', weights?: { w_sim?: number, w_imp?: number, w_rec?: number, pinBoost?: number }, now?: number, recencyHalfLifeMs?: number, vectorAdapter?: { embedText: (text: string) => Promise<number[]> | number[], queryVector: (input: { vector: number[], k?: number, filter?: Record<string, unknown> }) => Promise<Array<{ id: string, score: number }>> | Array<{ id: string, score: number }> }, embedText?: (value: string) => Promise<number[]> | number[] }} params
 * @returns {Promise<import('./schema.js').MemoryRecord[]>}
 */
export async function filterAndRankMemories(memories, params) {
  const {
    agent_id,
    query = '',
    tags = [],
    timeframe,
    k = 10,
    pinnedPreference = 'prefer',
    weights = {},
    now = Date.now(),
    recencyHalfLifeMs = DEFAULT_RECENCY_HALF_LIFE_MS,
    vectorAdapter,
    embedText,
  } = params;

  const mergedWeights = {
    ...DEFAULT_WEIGHTS,
    ...weights,
  };

  const filtered = memories.filter((memory) => {
    if (memory.agent_id !== agent_id) return false;
    return matchesMetadataFilters(memory, { tags, timeframe, pinnedPreference });
  });

  const similarityById = await buildSimilarityIndex(filtered, {
    query,
    agent_id,
    k,
    vectorAdapter,
    embedText,
  });

  return filtered
    .map((memory) => {
      const memoryTimestamp = Number.isFinite(memory.last_seen) ? memory.last_seen : memory.created_at;
      const recencyDecay = computeRecencyDecay(memoryTimestamp, now, recencyHalfLifeMs);
      const similarity = similarityById.get(memory.id) ?? 0;
      const pinBoost = memory.pinned && pinnedPreference !== 'exclude' ? mergedWeights.pinBoost : 0;

      const score = (similarity * mergedWeights.w_sim)
        + (memory.importance * mergedWeights.w_imp)
        + (recencyDecay * mergedWeights.w_rec)
        + pinBoost;

      return { memory, score };
    })
    .sort((left, right) => right.score - left.score)
    .slice(0, k)
    .map((entry) => entry.memory);
}

/**
 * @param {{ updateMemoryUsage: (id: string, lastSeen?: number) => Promise<unknown> }} repository
 * @param {string[]} ids
 * @param {number} [lastSeen]
 */
export async function updateMemoryUsage(repository, ids, lastSeen = Date.now()) {
  await Promise.all(ids.map((id) => repository.updateMemoryUsage(id, lastSeen)));
}

export { cosineSimilarity };
