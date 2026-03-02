# Semantic Vector Index Integration Plan

Status: In Progress (updated 2026-03-02)  
Branch target: `beta`  
Scope: Legacy TUI + Textual TUI v2 + CLI + API

## 1) Goal

Add semantic retrieval for knowledge-base content (documents, notes, titles, tags, graph context) without changing SeedPass canonical sync semantics or deterministic secret generation behavior.

## 2) Key Decision

Use a **local derived vector index per profile/device**.

Do not sync embeddings in Phase 1.

Canonical vault/index data remains the only synced source of truth. Vectors are a rebuildable cache derived from synced data.

## 3) Why Local-Only First

1. Privacy: embeddings can leak semantic content.
2. Portability: embedding model/version drift across devices is common.
3. Stability: avoids index incompatibility in cross-device sync.
4. Simplicity: no changes required to existing sync payload schema.

## 4) Data Eligibility Policy

Default include (non-secret KB-centric):

1. `label` / title
2. `notes`
3. `document` content
4. tags
5. graph link metadata (relation + note + neighbor label where available)

Default exclude:

1. generated secrets and private key material
2. seed phrases
3. TOTP secrets/codes
4. high-risk private fields

Policy controls:

1. per-kind index enable/disable
2. optional per-field allowlist/denylist
3. respect lock/session constraints for retrieval paths

## 5) Architecture

### 5.1 New Core Components

1. `seedpass.core.semantic_index`:
- chunking/normalization
- embedding adapter interface
- local vector store adapter
- metadata schema/versioning

2. `SemanticIndexService` (thread-safe wrapper):
- rebuild profile index
- incremental upsert/remove
- semantic search API
- health/status/report

### 5.2 Storage

Per-profile local path (example):

`~/.seedpass/<fingerprint>/semantic_index/`

Artifacts:

1. vector store files
2. index manifest (`model_id`, dimensions, schema version, timestamps)
3. source hash map for incremental updates

### 5.3 Event Hooks

Index updates on:

1. entry add/modify/archive/restore/delete
2. tag/field/link operations that change indexable content
3. profile switch/load/import sync completion

## 6) Sync and Lifecycle Model

On new device/profile bootstrap:

1. run existing sync/import
2. mark semantic index stale/unbuilt
3. trigger background build
4. expose build progress/status

On incremental change:

1. compute affected entry IDs
2. re-embed changed chunks only
3. upsert vectors + metadata

On model/schema change:

1. invalidate manifest
2. rebuild full local index

## 7) Interface Integration

## 7.1 Legacy TUI

Add settings + search affordances:

1. `Semantic Search: on/off`
2. `Rebuild semantic index`
3. `Semantic index status`
4. search mode toggle: keyword vs hybrid (keyword + semantic)

## 7.2 Textual TUI v2

Palette commands:

1. `semantic-status`
2. `semantic-build`
3. `semantic-rebuild`
4. `semantic-search <query>`
5. `search-mode <keyword|hybrid|semantic>`

UI surfaces:

1. top ribbon indicator (`SEM: ready/building/stale/off`)
2. results annotation showing semantic score + matched context

## 7.3 CLI

Proposed command group:

`seedpass semantic ...`

Commands:

1. `seedpass semantic status`
2. `seedpass semantic build`
3. `seedpass semantic rebuild`
4. `seedpass semantic search "<query>" --k N --kind document --json`
5. `seedpass semantic config --enabled true --mode hybrid`

## 7.4 API

Proposed endpoints:

1. `GET /api/v1/semantic/status`
2. `POST /api/v1/semantic/build`
3. `POST /api/v1/semantic/rebuild`
4. `POST /api/v1/semantic/search`

Request examples:

1. query text
2. filters (`kinds`, tags, archive scope)
3. mode (`semantic`, `hybrid`)

Response includes:

1. entry ID and summary
2. semantic score
3. matched chunk excerpt
4. optional graph-neighbor IDs

## 8) Search Strategy

Default: **hybrid retrieval**.

Pipeline:

1. lexical pre-filter (existing search/tags/kind/archive)
2. semantic top-k retrieval
3. lightweight rerank combining lexical + semantic + graph proximity
4. return ranked candidates

## 9) Security and Privacy Controls

1. Explicit opt-in toggle per profile.
2. High-risk kinds excluded by default.
3. Index files encrypted at rest if feasible through existing vault keying; if not in first cut, keep local-only and document risk explicitly.
4. No embeddings in sync payload by default.
5. Honor lock state: semantic retrieval disabled or restricted while locked.
6. Audit log events for semantic build/rebuild/search in agent/API contexts.

## 10) Determinism and Invariants

SeedPass deterministic artifact rules remain unchanged for secrets/keys/totp derivations.

Semantic index is a derived retrieval cache and:

1. must never influence cryptographic derivation outputs
2. must never alter canonical vault records as source-of-truth
3. must be safe to delete/rebuild at any time

## 11) Testing Plan

Unit tests:

1. chunking and field-selection policy
2. incremental update diffing
3. model/schema invalidation and rebuild triggers

Integration tests:

1. new profile bootstrap -> build triggered
2. synced import -> index rebuild path
3. CRUD updates -> incremental upsert/remove
4. lock mode behavior

Interface tests:

1. legacy TUI semantic status/build/search controls
2. TUI v2 palette semantic commands
3. CLI semantic command suite
4. API semantic endpoints and auth guards

Scale tests:

1. semantic retrieval latency and memory usage over KB stress datasets
2. hybrid ranking quality smoke checks

## 12) Rollout Phases

## Phase A: Core scaffolding (no UI)

1. [x] add service interfaces + local store abstraction
2. [x] add index manifest + per-profile storage layout
3. [x] add offline build/rebuild/status operations

Exit:

1. [x] CLI-only smoke works (`semantic status/build/search`)

## Phase B: CLI + API

1. [x] expose semantic commands in CLI
2. [x] expose semantic endpoints in API
3. [x] add initial tests for core + CLI + API
4. [ ] add lock/policy guard refinements for high-risk partitions and audit logging

Exit:

1. [x] interface tests pass for current endpoints/commands
2. [ ] audit and lock-policy behavior validated end-to-end

## Phase C: TUI integration

1. [ ] wire legacy TUI settings/search hooks
2. [ ] wire TUI v2 palette commands + ribbon/status indicators
3. [ ] add hybrid search mode toggles

Exit:

1. both TUIs can build/check/search semantic index reliably

## Phase D: Hardening and optional sync research

1. evaluate encrypted local vector store mode
2. evaluate optional embedding sync (off by default) with strict policy controls
3. add production metrics and runbooks

Exit:

1. readiness checklist sign-off

## 13) Open Decisions

1. Embedding model/runtime choice and offline availability constraints.
2. On-disk vector backend selection.
3. Whether encrypted-at-rest vector files are mandatory in Phase A or phased into hardening.
4. Whether semantic search is enabled-by-default for new profiles or opt-in.

## 14) Recommended Immediate Next Steps

1. Complete Phase C integration in both TUIs (`semantic-status/build/rebuild/search` + status indicator).
2. Add incremental update hooks on entry/link/tag mutations (avoid full rebuild for small edits).
3. Add hybrid ranking mode (`keyword|hybrid|semantic`) with explicit config + API contract.
4. Add audit logging and lock-policy tests for semantic operations in agent/API contexts.
5. Run KB scale benchmark with semantic index enabled and record latency/memory evidence.

## 15) Progress Snapshot (2026-03-02)

Implemented:

1. `seedpass.core.semantic_index` local derived index with profile-local manifest/records.
2. `semantic_index_enabled` profile config flag and config service wrappers.
3. `SemanticIndexService` in core API layer.
4. CLI commands:
- `seedpass semantic status|enable|disable|build|rebuild|search`
5. API endpoints:
- `GET /api/v1/semantic/status`
- `POST /api/v1/semantic/build`
- `POST /api/v1/semantic/rebuild`
- `POST /api/v1/semantic/search`
- `POST /api/v1/semantic/config`
6. Initial tests for core service/index, CLI commands, and API endpoints.

Not yet implemented:

1. Legacy TUI semantic controls.
2. TUI v2 semantic palette integration/ribbon indicator.
3. True embedding backend and vector DB adapter (current implementation is token-overlap baseline).
4. Incremental mutation hooks and hybrid ranking mode.
