# Sync Conflict Contract

This document defines the deterministic merge contract for index payloads handled by:

- `seedpass.core.encryption.EncryptionManager.decrypt_and_save_index_from_nostr(..., merge=True)`
- `seedpass.core.sync_conflict.merge_index_payloads(...)`

## Goals

- Deterministic convergence across devices.
- Idempotent replay of identical payloads.
- Safe deletion semantics that prevent stale resurrection.

## Merge Strategy

Current strategy ID:

- `modified_ts_hash_tombstone_v2`

Per-entry merge rules:

1. Higher `modified_ts` wins.
2. If `modified_ts` is equal, tie-break by canonical entry hash.
3. On equal timestamp, selected fields are union-merged deterministically:
   - `tags` and `custom_fields` use canonical sorted union.
   - Optional kind-specific fields are backfilled when one side is empty.
4. `archived` at equal timestamp uses conservative OR semantics.

## Tombstone Semantics

Deletions are represented in `_sync_meta.tombstones`:

```json
{
  "_sync_meta": {
    "tombstones": {
      "<index>": {
        "deleted_ts": 1710000000,
        "entry_hash": "<optional-entry-hash>",
        "event_hash": "<deterministic-event-hash>",
        "source": "<optional-source-tag>"
      }
    }
  }
}
```

Rules:

1. Tombstone with higher `deleted_ts` wins.
2. Equal `deleted_ts` tie-breaks by tombstone `event_hash`.
3. Entry vs tombstone:
   - `entry.modified_ts < deleted_ts`: entry removed.
   - `entry.modified_ts > deleted_ts`: tombstone dropped.
   - equal timestamp: event hash tie-break.

## `_sync_meta` Contract

`_sync_meta` is merged deterministically and currently includes:

- `strategy`: merge strategy identifier.
- `last_merge_ts`: deterministic max timestamp observed during merge.
- `source_count`: count of tracked source tags.
- `sources`: lexicographically sorted source tags (bounded list).
- `tombstones`: bounded map of delete markers.

`last_merge_ts` must not depend on wall-clock time; it is derived from existing/incoming metadata and payload timestamps so replaying the same payload yields identical state.

## Replay and Ordering Guarantees

- Replaying the same payload must be idempotent.
- Applying stale payloads must not override newer state.
- Stale re-adds must not resurrect entries deleted by newer tombstones.
- Newer re-creates can legitimately supersede older tombstones.

## Retention

- Tombstones are retained in a bounded map (`TOMBSTONE_RETENTION_CAP`) to prevent unbounded metadata growth.
- The cap logic is deterministic.

## Test Coverage

Core invariants are covered in `src/tests/test_delta_merge.py`, including order independence, replay idempotency, stale replay handling, and tombstone convergence.
