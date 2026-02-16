/**
 * @typedef {{ query: (sql: string, params?: unknown[]) => Promise<{ rows?: any[], rowCount?: number }> }} QueryableDb
 */

/**
 * @param {QueryableDb} db
 */
export function createMemoryRepository(db) {
  return {
    /**
     * @param {import('./schema.js').MemoryRecord} memory
     */
    async insertMemory(memory) {
      const result = await db.query(
        `INSERT INTO memories (
          id, schema_version, agent_id, session_id, type, summary,
          content, tags, importance, embedding_id, source,
          created_at, last_seen, ttl_days, merged_into, pinned
        ) VALUES (
          $1, $2, $3, $4, $5, $6,
          $7::jsonb, $8::text[], $9, $10, $11::jsonb,
          $12, $13, $14, $15, $16
        )
        ON CONFLICT (id) DO UPDATE SET
          summary = EXCLUDED.summary,
          content = EXCLUDED.content,
          tags = EXCLUDED.tags,
          importance = EXCLUDED.importance,
          embedding_id = EXCLUDED.embedding_id,
          source = EXCLUDED.source,
          last_seen = EXCLUDED.last_seen,
          ttl_days = EXCLUDED.ttl_days,
          merged_into = EXCLUDED.merged_into,
          pinned = EXCLUDED.pinned,
          updated_at = NOW()
        RETURNING *`,
        [
          memory.id,
          memory.schema_version,
          memory.agent_id,
          memory.session_id,
          memory.type,
          memory.summary,
          JSON.stringify({ text: memory.content }),
          memory.tags,
          memory.importance,
          memory.embedding_id,
          JSON.stringify({ value: memory.source }),
          memory.created_at,
          memory.last_seen,
          memory.ttl_days,
          memory.merged_into,
          memory.pinned,
        ]
      );

      return result.rows?.[0] ?? null;
    },

    /**
     * @param {string} id
     * @param {number} [lastSeen]
     */
    async updateMemoryUsage(id, lastSeen = Date.now()) {
      const result = await db.query(
        `UPDATE memories
         SET last_seen = $2, updated_at = NOW()
         WHERE id = $1
         RETURNING *`,
        [id, lastSeen]
      );

      return result.rows?.[0] ?? null;
    },

    /**
     * @param {{ cutoff: number, limit?: number }} options
     */
    async listPruneCandidates(options) {
      const limit = Number.isFinite(options.limit) ? Number(options.limit) : 500;
      const result = await db.query(
        `SELECT *
         FROM memories
         WHERE pinned = FALSE
           AND (merged_into IS NOT NULL OR last_seen < $1)
         ORDER BY last_seen ASC
         LIMIT $2`,
        [options.cutoff, limit]
      );

      return result.rows ?? [];
    },

    /**
     * @param {string} id
     * @param {string} mergedInto
     */
    async markMerged(id, mergedInto) {
      const result = await db.query(
        `WITH updated AS (
           UPDATE memories
           SET merged_into = $2, updated_at = NOW()
           WHERE id = $1
           RETURNING id
         )
         INSERT INTO memory_links (from_memory_id, to_memory_id, relation_type)
         SELECT id, $2, 'merged_into' FROM updated
         ON CONFLICT (from_memory_id, to_memory_id, relation_type) DO NOTHING
         RETURNING from_memory_id`,
        [id, mergedInto]
      );

      return (result.rowCount ?? 0) > 0;
    },

    /**
     * @param {string} id
     * @param {boolean} pinned
     */
    async setPinned(id, pinned) {
      const result = await db.query(
        `WITH updated AS (
           UPDATE memories
           SET pinned = $2, updated_at = NOW(), last_seen = $3
           WHERE id = $1
           RETURNING id, pinned
         )
         INSERT INTO memory_admin_flags (memory_id, pinned, pinned_at, updated_at)
         SELECT id, pinned, CASE WHEN pinned THEN NOW() ELSE NULL END, NOW() FROM updated
         ON CONFLICT (memory_id) DO UPDATE SET
           pinned = EXCLUDED.pinned,
           pinned_at = EXCLUDED.pinned_at,
           updated_at = EXCLUDED.updated_at
         RETURNING memory_id, pinned`,
        [id, pinned, Date.now()]
      );

      return result.rows?.[0] ?? null;
    },

    /**
     * @param {string} id
     */
    async getMemoryById(id) {
      const result = await db.query(
        `SELECT *
         FROM memories
         WHERE id = $1
         LIMIT 1`,
        [id]
      );

      return result.rows?.[0] ?? null;
    },

    /**
     * @param {{ agent_id?: string, type?: string, pinned?: boolean, limit?: number, offset?: number }} [filters]
     */
    async listMemories(filters = {}) {
      const where = [];
      const params = [];

      if (typeof filters.agent_id === 'string' && filters.agent_id.length > 0) {
        params.push(filters.agent_id);
        where.push(`agent_id = $${params.length}`);
      }

      if (typeof filters.type === 'string' && filters.type.length > 0) {
        params.push(filters.type);
        where.push(`type = $${params.length}`);
      }

      if (typeof filters.pinned === 'boolean') {
        params.push(filters.pinned);
        where.push(`pinned = $${params.length}`);
      }

      const limit = Number.isFinite(filters.limit) ? Math.max(1, Number(filters.limit)) : 100;
      const offset = Number.isFinite(filters.offset) ? Math.max(0, Number(filters.offset)) : 0;
      params.push(limit);
      const limitPos = params.length;
      params.push(offset);
      const offsetPos = params.length;

      const whereClause = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';
      const result = await db.query(
        `SELECT *
         FROM memories
         ${whereClause}
         ORDER BY last_seen DESC
         LIMIT $${limitPos}
         OFFSET $${offsetPos}`,
        params
      );

      return result.rows ?? [];
    },
  };
}
