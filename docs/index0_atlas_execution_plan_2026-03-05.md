# Index0 Atlas Execution Plan (2026-03-05)

Status: In Progress  
Branch target: `beta`  
Scope: Core index payload, Nostr sync, hierarchy navigation, future KB and agent workflows
Companion plan:
- `docs/atlas_search_graph_integration_plan_2026-03-05.md`

Progress update (2026-03-05):

1. Phase 1 foundation landed:
   - reserved `_system.index0` payload namespace
   - deterministic normalization and merge helpers
   - optional manifest metadata model support
2. Phase 1 CRUD/link emission landed:
   - `index0_event` emission for entry create/modify/archive/restore/delete
   - `index0_event` emission for link add/remove
   - writer head updates and profile-path-derived scope stamping
3. Phase 1 checkpoint/manifest slice landed:
   - deterministic daily checkpoint rebuild from canonical event streams
   - bounded checkpoint retention per writer
   - manifest publication of current `index0` checkpoint hashes and stream heads
4. Phase 1 canonical views slice landed:
   - deterministic synced `children_of`, `counts_by_kind`, and `recent_activity`
   - view rebuild integrated into the same payload compaction path as checkpoints
   - lightweight atlas read helpers for future clients
5. Atlas consumer slice landed:
   - `AtlasService` added at the core API boundary
   - first v3 wayfinder/atlas consumer landed via palette command and screen
   - main workspace now shows an always-visible atlas strip
   - atlas screen now supports direct entry jumps and quick filter jumps
6. Next:
   - deeper search/navigation handoff
   - agent-facing atlas workflows
   - later event-pruning compaction policy if needed

Current accomplished scope summary:

1. canonical atlas storage exists inside `_system.index0`
2. canonical event emission exists for CRUD and link flows
3. checkpoint rebuild and manifest validation metadata exist
4. first synced canonical views exist
5. service-layer atlas reads exist
6. v3 already exposes atlas data in:
   - dedicated wayfinder screen
   - workspace strip
   - actionable entry and filter jumps

## 1) Goal

Implement `index0` as the canonical encrypted atlas for SeedPass:

1. record what exists
2. record what changed
3. expose deterministic wayfinding state for users and agents
4. preserve existing SeedPass sync, merge, and security guarantees

Working slogan:

`Index0 is the atlas: it records what exists, what changed, and how to navigate it.`

## 2) Beta Branch Baseline To Reuse

This plan is grounded in the current `beta` branch, not a greenfield design.

Existing contracts already in place:

1. Nostr sync uses manifest + snapshot chunks + deltas:
   - manifest `30070`
   - snapshot chunk `30071`
   - delta `30072`
   - references: `docs/SPEC.md`, `docs/nostr_setup.md`, `src/nostr/backup_models.py`, `src/nostr/snapshot.py`
2. Deterministic convergence already exists through `modified_ts_hash_tombstone_v2`:
   - references: `docs/sync_conflict_contract.md`, `src/seedpass/core/sync_conflict.py`
3. Retention caps already exist for unbounded metadata growth:
   - current example: tombstone retention cap in `src/seedpass/core/sync_conflict.py`
4. Hierarchy and namespace reset are already part of the product model:
   - key hierarchy: `docs/SPEC.md`
   - namespace reset / `nostr_account_idx`: `docs/nostr_namespace_reset.md`, `src/seedpass/core/state_manager.py`
5. Entry graph links already provide typed relationships between artifacts:
   - reference: `docs/entry_graph.md`
6. Semantic retrieval already has the correct architectural shape for derived caches:
   - local-only derived index, not canonical sync state
   - reference: `docs/semantic_vector_index_plan.md`

## 3) Core Design Decision

`index0` should live inside the existing encrypted index payload and ride the existing snapshot/delta pipeline.

Recommendation for `beta`:

1. Do not create a separate database or alternate sync protocol.
2. Do not put `index0` records into the user `entries` map initially.
3. Add a reserved top-level system namespace in the canonical payload, then expose entry-like adapters later if needed.

Recommended payload shape:

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

## 4) Why `_system.index0` Instead Of User `entries`

The current `beta` code strongly assumes user entries are numeric IDs:

1. create/update flows allocate integer IDs in `src/seedpass/core/entry_management.py`
2. retrieve/modify/list paths index into `entries[str(index)]`
3. several CLI/TUI/API paths expect user-facing entry IDs to remain numeric

Shoving reserved `index0` records directly into `entries` would create unnecessary compatibility risk.

So the practical `beta` implementation is:

1. canonical storage inside the same synced payload
2. separate reserved namespace for system-owned records
3. optional projection into UI/API later as a virtual view layer

This still satisfies the main requirement: `index0` remains first-class canonical state inside the same encrypted, merged, synced vault.

## 5) What `index0` Must Contain

`index0` should contain three record classes.

### 5.1 `index0_event`

Ground-truth change records.

Purpose:

1. append change history
2. capture hierarchy and relationship mutations
3. support audit, sync replay validation, and activity feeds

Minimum fields:

```json
{
  "event_id": "sha256(...)",
  "event_type": "entry_created",
  "subject_type": "entry",
  "subject_id": "42",
  "subject_kind": "document",
  "scope_path": "seed/<root>/managed/<child>",
  "actor_type": "user",
  "actor_id": "<profile fingerprint or agent id>",
  "writer_id": "<logical writer id>",
  "modified_ts": 1760000000,
  "prev_hash": "<optional prior hash in writer stream>",
  "classification": "internal",
  "partition": "standard",
  "policy_ref": "<optional policy stamp or rule id>",
  "payload_ref": {
    "entry_id": "42"
  },
  "links": [
    {
      "target_id": "42",
      "relation": "describes"
    }
  ],
  "tags": ["kb", "chat", "audit"],
  "visibility": "private",
  "integrity_hash": "sha256(...)"
}
```

Initial event types:

1. `entry_created`
2. `entry_modified`
3. `entry_deleted`
4. `entry_archived`
5. `entry_restored`
6. `link_added`
7. `link_removed`
8. `profile_added`
9. `profile_removed`
10. `agent_added`
11. `agent_removed`
12. `sync_snapshot_published`
13. `sync_delta_applied`
14. `nostr_message_indexed`
15. `document_indexed`

### 5.2 `index0_checkpoint`

Deterministic integrity and compaction anchors.

Purpose:

1. summarize older event windows
2. cap growth
3. store checkpoint hashes that manifests can reference

Minimum fields:

```json
{
  "checkpoint_id": "cp-000001",
  "window_start_ts": 1760000000,
  "window_end_ts": 1760086400,
  "event_count": 512,
  "head_hashes": {
    "writer:<root>": "abc123",
    "writer:<managed-user>": "def456"
  },
  "summary_hash": "sha256(...)",
  "rollup": {
    "events_by_type": {
      "entry_modified": 300,
      "nostr_message_indexed": 90
    },
    "subjects_by_kind": {
      "document": 120,
      "note": 90
    }
  },
  "modified_ts": 1760086400
}
```

### 5.3 `index0_view`

Derived, regeneratable navigation caches.

Purpose:

1. speed up browsing
2. avoid recomputing common hierarchy and activity summaries
3. support future agent navigation and hybrid search routing

Initial views:

1. `children_of:<scope>`
2. `recent_activity:<scope>`
3. `top_tags:<scope>`
4. `counts_by_kind:<scope>`
5. `hot_nodes:<scope>`
6. `conversation_index:<scope>`

Views are not the source of truth. They must always be rebuildable from canonical entries plus `index0_event` and `index0_checkpoint`.

### 5.4 Canonical vs local derived views

This is an important design refinement for `beta`.

Do not sync every derived navigation or search view.

Recommended split:

1. `canonical_views`:
   - low-cardinality, deterministic, cross-device-useful summaries
   - examples: `children_of`, `counts_by_kind`, compact `recent_activity`
2. local derived views:
   - expensive, high-churn, or personalization-oriented caches
   - examples: semantic neighbor expansions, ranking caches, UI-specific hotlists

Rules:

1. only sync views that materially improve restore/bootstrap/navigation across devices
2. keep search-heavy and high-cardinality projections local
3. treat `view_manifest` as the contract for what canonical views exist and how they are versioned

This keeps `index0` useful without recreating a second bloated database inside the vault payload.

## 6) Hash Chaining And Tamper Evidence

For `beta`, use lightweight tamper evidence instead of a full Merkle epoch system.

### 6.1 Event integrity

Each `index0_event` stores:

1. `integrity_hash`: canonical hash of the event payload
2. `prev_hash`: optional hash of the prior event in the same logical writer stream
3. `writer_id`: deterministic stream identifier

### 6.2 Why writer streams instead of one global chain

A single global append-only chain is fragile under concurrent multi-device mutation.

The current `beta` branch is already multi-device and delta-merge oriented, so the safer MVP is:

1. hash-chain per logical writer stream
2. deterministic checkpoint rollups that record the set of stream heads
3. manifest-level checkpoint metadata for restore validation

This preserves tamper evidence without forcing total ordering across all concurrent writers.

### 6.3 Manifest checkpoint metadata

Extend manifest payloads to optionally include:

```json
{
  "index0_checkpoint_id": "cp-000001",
  "index0_checkpoint_hash": "sha256(...)",
  "index0_stream_heads": {
    "writer:<root>": "abc123"
  }
}
```

Validation path on restore:

1. restore latest snapshot
2. replay newer deltas
3. recompute current `index0` checkpoint/head material
4. compare against manifest metadata
5. raise warning or fail closed based on policy setting

## 7) Deterministic Merge Contract For `index0`

`index0` must not bypass the current merge contract. It should extend it.

Required behavior:

1. base entries still merge with `modified_ts_hash_tombstone_v2`
2. `_system.index0.events` merges by `event_id`
3. identical `event_id` payloads are idempotent
4. equal-subject competing events resolve deterministically using:
   - `modified_ts`
   - canonical event hash
   - tombstone/deletion precedence where applicable
5. checkpoints and views are regenerated or selected deterministically

Implementation direction:

1. add a dedicated `merge_system_index0(...)` helper beside `merge_index_payloads(...)`
2. fold its result into the canonical merged payload
3. keep all timestamps replay-safe and derived from payload data, not wall clock, where merge state is computed

## 8) Deterministic Compaction

`index0` will grow quickly if it tracks chat, docs, and agent activity.

MVP compaction rules:

1. keep recent raw events under a deterministic retention window
2. roll older events into checkpoints
3. preserve enough raw events to support recent activity and recent forensic review
4. preserve checkpoint hashes indefinitely or under a much larger cap

Recommended deterministic policy:

1. retain last `N` raw events per writer stream
2. retain last `M` days of raw events globally
3. compact older events into fixed windows:
   - daily first
   - weekly later if scale requires
4. compute checkpoint IDs from canonical window bounds, not device-local counters

Important:

Compaction must be deterministic from payload state alone so two devices compacting the same data converge to the same post-compaction state.

Recommended initial defaults:

1. keep checkpoints indefinitely until an explicit larger cap is required
2. keep only compact canonical views in sync
3. rebuild local heavy views on demand after sync or unlock

## 9) Nostr And Communication Scope

The goal is not to make `index0` hold every byte of communication content.

Recommended split:

1. canonical communication artifacts remain normal vault data or future dedicated entry kinds
2. `index0` records:
   - existence
   - ownership/visibility metadata
   - hierarchy placement
   - conversation references
   - recent activity summaries
3. optional future message/document bodies continue to live in encrypted entries or high-risk partitions

This keeps `index0` useful as a map without turning it into a giant bottleneck payload.

Retention and exposure rules:

1. public Nostr references may be stored as lightweight refs in canonical vault data
2. private DM content should default to encrypted entry payloads or high-risk partitions, not inline `index0_event` bodies
3. `index0` should store enough metadata to navigate to a message, not enough to become the message store

## 10) Hierarchy And Permission Model

`index0` must not weaken SeedPass security posture.

Rules:

1. `index0` is encrypted inside the same profile payload as the rest of the vault
2. `index0` only reveals what the active profile is already authorized to decrypt
3. manager access to subordinate data should continue to use the existing hierarchy and profile-loading model
4. future agent access should reuse approval/export/partition controls rather than adding an `index0` bypass
5. event metadata for high-risk partitions should be minimal and policy-aware

Policy alignment:

1. reuse policy stamps / policy-as-code identifiers where policy-shaped access affects atlas visibility
2. reuse audit expectations from the agent autonomy plan rather than inventing a second audit vocabulary
3. keep `classification` and `partition` fields small, deterministic, and non-secret

Institutional knowledge model:

1. each user/agent continues producing canonical artifacts in their scope
2. `index0` links those artifacts into a searchable atlas
3. manager-level profiles can build broader navigation views when they already have legitimate access to those scopes

## 11) Interaction With Existing Roadmaps

### 11.1 TUI v2 plan

`index0` is not a prerequisite for the current TUI v2 parity/cutover work.

However, once present it directly improves:

1. real hierarchy navigation
2. recent activity surfaces
3. context-aware wayfinding
4. future conversation and KB sidebars

### 11.2 Semantic index plan

The semantic vector index should remain local-only derived state.

Recommended relationship:

1. `index0` is canonical synced atlas data
2. semantic vectors remain device-local derived retrieval data
3. semantic chunking can consume `index0_view` and graph context as ranking features

### 11.3 Entry graph plan

`index0` should reuse `links` conventions instead of inventing a second graph model.

## 12) Implementation Touchpoints In `beta`

Primary files likely to change:

1. `src/seedpass/core/sync_conflict.py`
   - add deterministic merge support for `_system.index0`
2. `src/seedpass/core/vault.py`
   - load/save/migration handling for `_system.index0`
3. `src/seedpass/core/encryption.py`
   - merge path for restored payloads
4. `src/nostr/backup_models.py`
   - manifest metadata extension for `index0` checkpoint fields
5. `src/nostr/snapshot.py`
   - publish/fetch manifest support for `index0` checkpoint metadata
6. `src/seedpass/core/entry_management.py`
   - emit `index0_event` records on create/update/delete/link actions
7. `src/seedpass/core/api.py`
   - expose atlas inspection/status endpoints
8. `src/seedpass/core/semantic_index.py`
   - optional future use of `index0_view` context during hybrid retrieval
9. `src/seedpass/core/state_manager.py`
   - only if local rebuild or validation state must be persisted
10. `src/seedpass/core/agent_export_policy.py`
   - if atlas reads need policy-shaped export or redaction behavior

## 13) Delivery Phases

## Phase 0: Spec And Schema Lock

Deliver:

1. finalize `_system.index0` payload shape
2. finalize event/checkpoint/view schemas
3. define manifest extension fields
4. define deterministic compaction contract

Exit criteria:

1. schema doc merged
2. migration strategy documented
3. no open ambiguity on user-entry ID compatibility

## Phase 1: Canonical Storage + Merge

Deliver:

1. payload migrations for `_system.index0`
2. `merge_system_index0(...)`
3. event ID and integrity hash helpers
4. deterministic checkpoint selection rules

Exit criteria:

1. replay idempotency holds
2. stale payloads cannot override newer `index0` state
3. merge order independence proven by tests

## Phase 2: Event Emission Hooks

Deliver:

1. emit events on entry CRUD
2. emit events on archive/restore
3. emit events on link add/remove
4. emit events on profile/agent lifecycle operations where already represented in core flows

Exit criteria:

1. user-visible mutations update `index0` automatically
2. no manual rebuild required for core audit path

## Phase 3: Manifest Checkpoints + Validation

Deliver:

1. extend manifest schema
2. write checkpoint metadata during snapshot publish
3. validate checkpoint/head metadata during restore
4. define warning vs hard-fail policy

Exit criteria:

1. snapshot/delta replay can verify `index0` checkpoint continuity
2. failure states are explicit and test-covered

## Phase 4: Deterministic Compaction

Deliver:

1. raw-event retention windows
2. checkpoint rollup generation
3. deterministic pruning
4. migration path for older payloads without checkpoints

Exit criteria:

1. event growth remains bounded
2. two devices compacting the same payload converge

## Phase 5: Read APIs And Wayfinder Views

Deliver:

1. atlas status API/CLI surface
2. recent activity feed
3. children-of and counts-by-kind views
4. hot-nodes and top-tags views

Exit criteria:

1. user/agent can navigate from atlas state without scanning the full vault
2. views can be rebuilt from canonical data

## Phase 6: Communication And KB Integration

Deliver:

1. add event hooks for future Nostr chat/document workflows
2. add message/conversation references
3. integrate atlas cues into KB and semantic search experiences
4. keep raw private communication content out of canonical atlas events

Exit criteria:

1. institutional knowledge use cases work without changing cryptographic source-of-truth rules

## 14) Testing Plan

Required new tests:

1. unit:
   - event hash generation
   - writer-stream hash chaining
   - checkpoint hash generation
   - deterministic compaction selection
2. merge:
   - order independence
   - replay idempotency
   - stale event rejection
   - concurrent writer-stream head preservation
3. migration:
   - old payload without `_system.index0` upgrades cleanly
   - namespace reset still works
4. Nostr sync:
   - manifest metadata round-trip
   - snapshot + delta restore validation
   - checkpoint mismatch handling
5. integration:
   - CRUD emits events
   - link operations emit events
   - archive/delete semantics converge
6. scale:
   - large KB/chat event volume
   - compaction boundedness

Likely test homes:

1. `src/tests/test_delta_merge.py`
2. new `src/tests/test_index0_merge.py`
3. new `src/tests/test_index0_compaction.py`
4. new `src/tests/test_index0_manifest_validation.py`
5. targeted API/CLI/TUI tests once read surfaces exist

## 15) Sequencing Against The Current Dev Plan

Recommended sequencing in `beta`:

1. now:
   - Phase 0 spec and schema lock
   - no conflict with current TUI work
2. after current cutover-critical TUI/security slices are stable:
   - Phases 1 through 3
3. after semantic hybrid hardening resumes:
   - Phase 5 atlas read surfaces and semantic interplay
4. after communication entry types or Nostr DM indexing lands:
   - Phase 6

Practical interpretation:

1. start the architecture/spec work immediately
2. do not let `index0` disrupt TUI parity closeout or current security readiness gates
3. implement core atlas plumbing as the next major core-data track once current cutover work is no longer the top release blocker

## 16) Open Design Questions

These should be resolved in Phase 0 before code lands:

1. should `writer_id` be profile-fingerprint based, device based, or actor based?
2. should checkpoint mismatch fail restore or warn and continue by default?
3. which communication payloads are canonical vault entries versus external references?
4. should manager-level aggregate atlas views be materialized or computed on demand?
5. should `writer_id` default to profile scope first and only later split by agent identity where needed?

## 17) Bottom Line

For the current `beta` branch, the right implementation is:

1. keep `index0` inside the existing encrypted snapshot/delta payload
2. model it as a reserved `_system.index0` atlas namespace
3. use lightweight hash-chained writer streams plus manifest checkpoint hashes
4. compact deterministically
5. expose fast navigation through rebuildable views

This gives SeedPass a canonical launch pad and map for institutional knowledge without abandoning the sync, determinism, and hierarchy model that `beta` already has.
