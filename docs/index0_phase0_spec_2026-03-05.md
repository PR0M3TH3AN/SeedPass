# Index0 Phase 0 Implementation Spec (2026-03-05)

Status: Proposed  
Branch target: `beta`  
Depends on: `docs/index0_atlas_execution_plan_2026-03-05.md`

## 1) Goal

Lock the Phase 0 implementation contract for `index0` so coding can begin without schema drift.

This document defines:

1. canonical payload schema
2. manifest extension fields
3. normalization and hashing rules
4. deterministic merge rules
5. deterministic compaction defaults
6. first implementation slice
7. first test matrix

## 2) Canonical Payload Contract

`index0` lives inside the same encrypted vault payload in a reserved namespace:

```json
{
  "schema_version": 3,
  "entries": {},
  "_sync_meta": {},
  "_system": {
    "index0": {
      "schema_version": 1,
      "events": {},
      "checkpoints": {},
      "canonical_views": {},
      "view_manifest": {},
      "heads": {},
      "stats": {}
    }
  }
}
```

Normalization requirements:

1. missing `_system` must be treated as `{}`
2. missing `_system.index0` must be initialized during load or merge
3. all `events`, `checkpoints`, `canonical_views`, `heads`, and `stats` members must be JSON objects
4. all keys must be ASCII strings
5. the canonical JSON hash function must use `sort_keys=True` and compact separators `(",", ":")`

## 3) Schema Definitions

### 3.1 `index0_event`

Storage key:

- `events[event_id]`

Required fields:

```json
{
  "event_id": "e:sha256hex",
  "event_type": "entry_created",
  "subject_type": "entry",
  "subject_id": "42",
  "subject_kind": "document",
  "scope_path": "seed/<root>/managed/<child>",
  "actor_type": "user",
  "actor_id": "<profile fingerprint or agent id>",
  "writer_id": "writer:<scope-or-profile>",
  "modified_ts": 1760000000,
  "prev_hash": "",
  "classification": "internal",
  "partition": "standard",
  "payload_ref": {
    "entry_id": "42"
  },
  "links": [],
  "tags": [],
  "visibility": "private",
  "integrity_hash": "sha256hex"
}
```

Optional fields:

```json
{
  "policy_ref": "<policy stamp or stable rule id>",
  "source": "entry_management",
  "source_event_id": "<nostr event id or external ref>",
  "summary": "<short safe summary>"
}
```

Enum constraints:

1. `event_type`:
   - `entry_created`
   - `entry_modified`
   - `entry_deleted`
   - `entry_archived`
   - `entry_restored`
   - `link_added`
   - `link_removed`
   - `profile_added`
   - `profile_removed`
   - `agent_added`
   - `agent_removed`
   - `sync_snapshot_published`
   - `sync_delta_applied`
   - `nostr_message_indexed`
   - `document_indexed`
2. `subject_type`:
   - `entry`
   - `profile`
   - `agent`
   - `conversation`
   - `document`
   - `sync`
3. `actor_type`:
   - `user`
   - `agent`
   - `system`
4. `classification`:
   - `public`
   - `internal`
   - `restricted`
   - `secret`
5. `partition`:
   - `standard`
   - `high_risk`
6. `visibility`:
   - `public`
   - `private`
   - `policy_scoped`

Normalization rules:

1. `event_id`, `subject_id`, `actor_id`, and `writer_id` are stored as strings
2. `modified_ts` must be an integer greater than zero
3. `prev_hash` defaults to `""`
4. `links` must use the same canonical link normalization rules already used for entries
5. `tags` must be unique and lexicographically sorted
6. `summary` must never contain secret material
7. `integrity_hash` is computed from the canonical event body excluding the `integrity_hash` field itself

### 3.2 `index0_checkpoint`

Storage key:

- `checkpoints[checkpoint_id]`

Required fields:

```json
{
  "checkpoint_id": "cp:day:2026-03-05:writer:<root>",
  "window_type": "day",
  "window_key": "2026-03-05",
  "writer_id": "writer:<root>",
  "window_start_ts": 1760000000,
  "window_end_ts": 1760086399,
  "event_count": 512,
  "head_hash": "sha256hex",
  "summary_hash": "sha256hex",
  "rollup": {
    "events_by_type": {},
    "subjects_by_kind": {},
    "subjects": []
  },
  "modified_ts": 1760086399
}
```

Normalization rules:

1. initial implementation supports only `window_type = "day"`
2. `checkpoint_id` must be deterministic from `window_type`, `window_key`, and `writer_id`
3. `subjects` must be a sorted unique list and capped deterministically
4. `summary_hash` is computed from the canonical checkpoint body excluding `summary_hash`

### 3.3 `canonical_view`

Storage key:

- `canonical_views[view_id]`

Required fields:

```json
{
  "view_id": "children_of:seed/<root>",
  "view_type": "children_of",
  "scope_path": "seed/<root>",
  "source_checkpoint_ids": [],
  "source_event_ids": [],
  "data": {},
  "modified_ts": 1760086400,
  "view_hash": "sha256hex"
}
```

Normalization rules:

1. only compact low-cardinality views are eligible for canonical sync in Phase 1
2. `data` must be deterministic and sorted by stable keys
3. `view_hash` is computed from the canonical view body excluding `view_hash`

### 3.4 `view_manifest`

Purpose:

1. declare canonical synced views
2. version view builders
3. make local rebuild policy explicit

Schema:

```json
{
  "version": 1,
  "canonical_view_types": [
    "children_of",
    "counts_by_kind",
    "recent_activity"
  ],
  "local_only_view_types": [
    "hot_nodes",
    "conversation_index",
    "semantic_neighbors"
  ],
  "builder_versions": {
    "children_of": 1,
    "counts_by_kind": 1,
    "recent_activity": 1
  }
}
```

### 3.5 `heads`

Purpose:

Track current writer-stream head hashes.

Schema:

```json
{
  "writer:<root>": {
    "event_id": "e:sha256hex",
    "head_hash": "sha256hex",
    "modified_ts": 1760086400
  }
}
```

Rules:

1. each `writer_id` has at most one head record
2. higher `modified_ts` wins
3. equal timestamp resolves by lexicographically larger `head_hash`

### 3.6 `stats`

Initial synced stats:

```json
{
  "event_count": 1280,
  "checkpoint_count": 14,
  "writer_count": 3,
  "last_compaction_ts": 1760086400,
  "last_validation_ts": 1760086400
}
```

Stats are advisory and deterministically derived. They are never the source of truth.

## 4) Manifest Extension Contract

The current manifest already carries snapshot metadata. Extend it with optional `index0` fields:

```json
{
  "ver": 1,
  "algo": "gzip",
  "chunks": [],
  "delta_since": 1760086400,
  "nonce": "base64...",
  "index0": {
    "schema_version": 1,
    "checkpoint_ids": [
      "cp:day:2026-03-05:writer:<root>"
    ],
    "checkpoint_hashes": {
      "cp:day:2026-03-05:writer:<root>": "sha256hex"
    },
    "stream_heads": {
      "writer:<root>": "sha256hex"
    }
  }
}
```

Manifest rules:

1. manifest `index0` section is optional for backward compatibility
2. restore must accept manifests with no `index0`
3. manifest `index0` metadata is validation material, not source-of-truth state
4. if present, it must be recomputable from the decrypted payload after replay

## 5) Hashing And ID Rules

### 5.1 Canonical helper

Use the same canonical JSON discipline already used by the sync layer:

```python
json.dumps(value, sort_keys=True, separators=(",", ":"))
```

### 5.2 Event body hash

Pseudo:

```python
def canonical_event_body(event):
    body = dict(event)
    body.pop("integrity_hash", None)
    return body

def compute_event_hash(event):
    return sha256(canonical(canonical_event_body(event)))
```

### 5.3 Event ID

For Phase 1, event IDs should be content-addressed and deterministic:

```python
event_id = "e:" + compute_event_hash(event)
```

This intentionally makes duplicate event publication idempotent.

### 5.4 Head hash

Pseudo:

```python
def compute_head_hash(event):
    marker = {
        "event_id": event["event_id"],
        "integrity_hash": event["integrity_hash"],
        "prev_hash": event.get("prev_hash", ""),
        "writer_id": event["writer_id"],
    }
    return sha256(canonical(marker))
```

### 5.5 Checkpoint ID

Pseudo:

```python
checkpoint_id = f"cp:day:{window_key}:{writer_id}"
```

### 5.6 Checkpoint hash

Pseudo:

```python
def compute_checkpoint_hash(checkpoint):
    body = dict(checkpoint)
    body.pop("summary_hash", None)
    return sha256(canonical(body))
```

## 6) Writer Model

Phase 1 writer rule:

1. `writer_id` defaults to profile scope, not device instance
2. format:
   - root profile: `writer:profile:<fingerprint>`
   - managed scope: `writer:profile:<fingerprint>:managed:<subject>`
   - agent scope later if needed: `writer:agent:<agent_id>`

Rationale:

1. profile-scoped writers are simpler and stable across devices
2. this fits current `beta` multi-device deterministic merge better than device-scoped streams
3. agent-specific streams can be added later without invalidating the contract

## 7) Deterministic Merge Rules

`merge_index_payloads(...)` remains the top-level orchestrator.

Add:

```python
merge_system_index0(current_index0, incoming_index0) -> merged_index0
```

### 7.1 Event merge

Rules:

1. merge by `event_id`
2. if only one side contains an event, keep it
3. if both sides contain the same `event_id` and canonical bodies match, keep one
4. if both sides contain the same `event_id` but bodies differ, pick the event with lexicographically larger canonical body hash and record a validation warning path later

This last case should be treated as corruption-suspicious and covered by tests even if it should not occur in normal generation.

### 7.2 Head merge

Rules:

1. merge by `writer_id`
2. higher `modified_ts` wins
3. equal timestamp resolves by larger `head_hash`

### 7.3 Checkpoint merge

Rules:

1. merge by `checkpoint_id`
2. if both sides contain the same `checkpoint_id` with different bodies, select lexicographically larger `summary_hash`
3. equal bodies remain idempotent

### 7.4 Canonical view merge

Rules:

1. merge by `view_id`
2. higher `modified_ts` wins
3. equal timestamp resolves by larger `view_hash`
4. local-only views must never be written into canonical synced payload

### 7.5 Stats merge

Rules:

1. stats are recomputed from merged payload where practical
2. if not recomputed, use deterministic max/union semantics only

## 8) Merge Pseudocode

```python
def merge_system_index0(current, incoming):
    cur = normalize_index0(current)
    inc = normalize_index0(incoming)

    merged_events = merge_events(cur["events"], inc["events"])
    merged_heads = merge_heads(cur["heads"], inc["heads"])
    merged_checkpoints = merge_checkpoints(
        cur["checkpoints"], inc["checkpoints"]
    )
    merged_views = merge_canonical_views(
        cur["canonical_views"], inc["canonical_views"], cur["view_manifest"], inc["view_manifest"]
    )
    merged_view_manifest = merge_view_manifest(
        cur["view_manifest"], inc["view_manifest"]
    )

    merged = {
        "schema_version": max(cur["schema_version"], inc["schema_version"]),
        "events": merged_events,
        "checkpoints": merged_checkpoints,
        "canonical_views": merged_views,
        "view_manifest": merged_view_manifest,
        "heads": merged_heads,
        "stats": recompute_stats(
            merged_events, merged_checkpoints, merged_heads
        ),
    }
    return compact_index0(merged)
```

## 9) Deterministic Compaction Defaults

Phase 1 compaction must stay intentionally simple.

Defaults:

1. raw event retention per writer:
   - keep last `512` raw events
2. raw event retention by age:
   - keep last `30` days
3. checkpoint window:
   - daily
4. canonical view retention:
   - keep only latest view per `view_id`
5. checkpoint subject list cap:
   - `128`

Compaction order:

1. group events by `writer_id`
2. within each writer, sort by:
   - `modified_ts`
   - `event_id`
3. materialize daily checkpoints for prunable windows
4. prune raw events only after checkpoint exists
5. recompute heads and stats

Guarantee:

If two devices compact the same normalized payload, they must produce the same payload.

## 10) Initial Builder Scope

The first code slice should not try to solve the full knowledge-base product.

Phase 1 implementation should include only:

1. `_system.index0` schema initialization and migration
2. event emission for:
   - entry create
   - entry modify
   - entry delete
   - entry archive
   - entry restore
   - link add
   - link remove
3. merge support
4. head maintenance
5. manifest `index0` metadata round-trip

Deferred until later phases:

1. communication-specific event emission
2. local rebuild daemons
3. UI-facing atlas panels
4. semantic interplay
5. policy-filtered atlas export

## 11) Failure Handling

Rules:

1. malformed `index0` objects must normalize to empty structures where safe
2. malformed individual events/checkpoints/views should be dropped during normalization if required fields are invalid
3. manifest `index0` mismatches should warn by default in the first implementation
4. hard-fail behavior can be added later behind policy/config

## 12) Test Matrix

### 12.1 Unit

1. `normalize_index0` fills defaults and drops malformed objects
2. `compute_event_hash` is stable
3. `compute_head_hash` is stable
4. `compute_checkpoint_hash` is stable
5. tag normalization is deterministic
6. checkpoint ID generation is deterministic

### 12.2 Merge

1. event merge is idempotent
2. event merge is order independent
3. conflicting same-`event_id` bodies resolve deterministically
4. head merge prefers newer `modified_ts`
5. equal timestamp head merge prefers larger `head_hash`
6. view merge rejects local-only view types in canonical payload

### 12.3 Replay / vault boundary

1. payload with `_system.index0` survives encrypt/decrypt round-trip
2. repeated merge through vault boundary is idempotent
3. stale payload replay cannot remove newer heads/checkpoints

### 12.4 Migration

1. old payload without `_system` upgrades cleanly
2. old payload with malformed `_system.index0` repairs cleanly
3. existing entry CRUD remains unchanged

### 12.5 Nostr manifest

1. manifest serializes and parses optional `index0`
2. restore accepts legacy manifest with no `index0`
3. restore warning path triggers on checkpoint/head mismatch

### 12.6 Integration

1. add entry emits `entry_created`
2. modify entry emits `entry_modified`
3. delete path emits `entry_deleted`
4. archive/restore emit expected events
5. link add/remove emit expected events

## 13) Implementation Order

Recommended coding order:

1. add normalization + hashing helpers in a new `index0` module
2. extend merge logic with `merge_system_index0`
3. extend manifest dataclass and serializer/parser
4. add payload migration/init in vault load path
5. emit events from entry-management hooks
6. add tests in lockstep

## 14) Definition Of Phase 0 Complete

Phase 0 is complete when:

1. this schema contract is accepted
2. manifest extension fields are accepted
3. merge and compaction rules are accepted
4. first implementation slice is accepted
5. test inventory is accepted

At that point, implementation can move directly into Phase 1 without reopening architecture questions.
