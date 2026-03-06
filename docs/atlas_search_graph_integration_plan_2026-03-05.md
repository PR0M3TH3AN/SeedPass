# Atlas, Search, and Graph Integration Plan (2026-03-05)

Status: In Progress  
Branch target: `beta`  
Depends on:
- `docs/dev_control_center.md`
- `docs/index0_atlas_execution_plan_2026-03-05.md`
- `docs/index0_phase0_spec_2026-03-05.md`
- `docs/semantic_vector_index_plan.md`

## 1) Goal

Define the next architecture layer above the current `index0` foundation so SeedPass can deliver:

1. one robust search surface
2. deterministic browsing and sorting
3. first-class linked-item navigation
4. clean integration between:
   - `index0` atlas
   - canonical tags
   - canonical links
   - local semantic/vector search

Working slogan:

`Index0 is the atlas, links are the graph, tags are the human taxonomy, and semantic search is the local retrieval accelerator.`

## 2) Current Baseline

As of this branch state, SeedPass already has:

1. canonical encrypted entries in the synced payload
2. canonical tags on entries
3. canonical typed links between entries
4. local semantic/vector indexing
5. `index0` inside `_system.index0` with:
   - deterministic event emission
   - deterministic checkpoints
   - manifest head/checkpoint publication
   - canonical synced views:
     - `children_of`
     - `counts_by_kind`
     - `recent_activity`
6. `AtlasService`
7. first v3 atlas consumers:
   - dedicated wayfinder screen
   - always-visible workspace strip
   - basic actionable entry/filter jumps

What is still missing is the integration layer that turns these ingredients into one coherent navigation and search system.

## 3) Architecture Principles

### 3.1 Keep the roles distinct

Use the following separation strictly:

1. `index0`
   - canonical synced atlas
   - hierarchy, activity, lightweight structural summaries
2. tags
   - canonical human classification
   - workflow labels and topical labels
3. links
   - canonical explicit graph edges
   - typed relationships between entries
4. semantic index
   - local derived retrieval structure
   - embeddings, semantic neighbors, ranking aids

### 3.2 Do not duplicate heavy data into `index0`

`index0` should not store:

1. embeddings
2. full-text indexes
3. large semantic neighbor caches
4. personalization-heavy ranking state

Those stay local and rebuildable.

### 3.3 Make one search surface, not four

Users should not need to choose between:

1. tag search
2. link search
3. semantic search
4. atlas search

The UI should expose one main search command and one structured filter/sort system. Internally, that search can use multiple ranking channels.

## 4) Target Search Model

## 4.1 Unified search modes

SeedPass should expose these modes:

1. `keyword`
2. `hybrid`
3. `semantic`
4. later: `graph`

Behavior:

1. `keyword`
   - lexical only
   - deterministic and explainable
2. `hybrid`
   - lexical + semantic + structural re-ranking
   - default when semantic index is enabled
3. `semantic`
   - semantic-first results with metadata re-ranking
4. `graph`
   - neighborhood-driven traversal and link expansion
   - later phase only

## 4.2 Ranking channels

Unified ranking should combine these channels:

1. lexical
   - label
   - notes
   - document content
   - custom fields
   - tags
   - link relation text
2. structural
   - same subtree / same scope
   - direct link proximity
   - shared tags
   - recent atlas activity
   - node importance from link degree and change frequency
3. semantic
   - vector similarity from local semantic index
4. recency
   - recent updates from `modified_ts` and `recent_activity`

Recommended baseline weighting in `hybrid` mode:

1. lexical: `0.40`
2. semantic: `0.35`
3. structural: `0.20`
4. recency: `0.05`

These weights should remain configurable in code, but not initially user-configurable.

## 4.3 Result contract

Create a single result contract used by TUI, CLI, future GUI, and agents:

```json
{
  "entry_id": 42,
  "label": "Project Plan",
  "kind": "document",
  "scope_path": "seed/<root>",
  "archived": false,
  "score": 0.8123,
  "score_breakdown": {
    "lexical": 0.40,
    "semantic": 0.27,
    "structural": 0.11,
    "recency": 0.03
  },
  "match_reasons": [
    "label_exact",
    "tag:docs",
    "linked_to:selected",
    "same_scope"
  ],
  "excerpt": "Short safe text excerpt",
  "linked_hits": [
    {
      "target_id": 17,
      "relation": "references"
    }
  ],
  "tags": ["docs", "planning"],
  "modified_ts": 1760086400
}
```

Rules:

1. `score_breakdown` is optional in compact UI lists, but must be available to the service layer
2. `match_reasons` should be user-safe and explainable
3. `excerpt` must never reveal secrets for secret-bearing kinds unless explicitly requested

## 5) Sorting and Filtering Spec

## 5.1 Filters

SeedPass should support these first-class filters:

1. kind
2. archived state
3. tags
4. relation type
5. subtree / scope path
6. root profile vs managed scope
7. linked-to current item
8. has-links
9. has-tags
10. recently modified

Later filters:

1. changed-by actor
2. high-activity nodes
3. semantic index available / unavailable

## 5.2 Sorting

Supported sort modes:

1. `relevance`
2. `modified_desc`
3. `modified_asc`
4. `label_asc`
5. `kind`
6. `created_desc`
7. `most_linked`
8. `most_active`

Rules:

1. `relevance` is default only when a query exists
2. without a query, default browsing sort should be structural:
   - current scope
   - recent activity
   - stable secondary ordering by label or entry id
3. ties must always resolve deterministically:
   - first by score
   - then by `modified_ts`
   - then by label
   - then by numeric `entry_id`

## 6) Linked Navigation Model

Linked item navigation should become first-class, not hidden in raw entry metadata.

Required linked views:

1. outgoing links
   - “this item links to”
2. incoming links
   - “linked from”
3. neighborhood summary
   - grouped by relation type

Required linked item card data:

1. `entry_id`
2. `label`
3. `kind`
4. `relation`
5. `scope_path`
6. `archived`

Baseline now implemented in code:
1. `SearchService.linked_neighbors(...)` returns deterministic incoming/outgoing neighbor cards
2. `SearchService.relation_summary(...)` returns grouped incoming/outgoing/combined relation counts
3. TUI v3 inspector now surfaces linked-item summaries and direct open-entry actions
4. TUI v3 grid now exposes explicit sort/filter/mode controls and preserves the active search query across refreshes
7. `modified_ts`

Required actions:

1. open target
2. jump in grid
3. filter by relation
4. expand neighborhood
5. search within neighbors

## 7) How `index0` Should Integrate With Tags, Links, and Semantic Search

## 7.1 Canonical atlas additions

Add these `index0` canonical views next:

1. `linked_neighbors:<scope>`
   - compact summary of link density and high-value connected nodes
2. `tag_counts:<scope>`
   - counts for tags within current scope
3. `link_counts_by_relation:<scope>`
   - counts for relation types in the current scope
4. later: `incoming_links:<entry_id>`
   - only if bounded and deterministic

These should stay compact and summary-oriented.

## 7.2 Local-only derived additions

Keep these local-only:

1. semantic neighbor expansions
2. ranking caches
3. user history / frequently opened nodes
4. personalized hotlists

## 7.3 Re-ranking semantic results with atlas data

Semantic results should be re-ranked using:

1. same scope
2. direct links to current item
3. shared tags
4. recent activity
5. link-degree / node importance

This makes semantic results feel grounded in SeedPass structure instead of fuzzy.

## 8) Service-Layer Plan

Add a new service layer path above `AtlasService`, not inside the TUI:

### 8.1 `SearchService`

Responsibilities:

1. expose unified search API
2. merge lexical, semantic, and structural scoring
3. apply filters and sorting
4. explain ranking reasons

Recommended methods:

1. `search(query, mode, filters, sort, scope_path=None, selected_entry_id=None)`
2. `suggest(query, scope_path=None)`
3. `neighbors(entry_id, relation=None, direction="both")`
4. `related(entry_id, mode="hybrid")`

### 8.2 `AtlasService` expansion

Add:

1. `neighbors(entry_id)`
2. `incoming_links(entry_id)`
3. `outgoing_links(entry_id)`
4. `tag_summary(scope_path=None)`
5. `relation_summary(scope_path=None)`

## 9) TUI v3 Plan

## 9.1 Phase 1: Search and filter foundation

Deliverables:

1. unified search command path using `SearchService`
2. explicit sort control
3. explicit filter panel/state model
4. result rows show:
   - label
   - kind
   - tag summary
   - linked indicator
   - relevance or modified hint

## 9.2 Phase 2: Linked item navigation

Deliverables:

1. linked-items section in inspector
2. incoming/outgoing relation browsing
3. open-linked-item shortcuts
4. relation filters

## 9.3 Phase 3: Atlas-driven navigation

Deliverables:

1. promote wayfinder from helper to true landing/navigation layer
2. make atlas strip clickable or command-driven for:
   - recent activity jump
   - kind counts jump
   - scope drilldown
3. integrate “search in current scope” and “search neighbors of current item”

## 9.4 Phase 4: Agent workflows

Deliverables:

1. structured atlas query helpers for agents
2. explainable result payloads
3. graph-neighborhood traversal helpers
4. safe summaries that avoid secret leakage by default

## 10) Development Phases

### Phase A: Search contract and service

Implement:

1. `SearchService`
2. unified result schema
3. deterministic filter/sort pipeline
4. hybrid scorer baseline

Exit criteria:

1. one service call can perform keyword/hybrid/semantic search
2. results include stable ordering and match reasons

Current status:

1. complete baseline in `src/seedpass/core/api.py`
2. unified result schema landed with score breakdown, match reasons, tags, linked-hit summaries, and safe excerpts
3. deterministic filter/sort pipeline landed for baseline modes and common sort orders
4. v3 entry grid now consumes `SearchService` as the primary search path
5. focused regression coverage landed in `src/tests/test_core_api_services.py` and `src/tests/test_tui_v3_smoke.py`

### Phase B: Atlas view expansion

Implement:

1. `tag_counts`
2. `link_counts_by_relation`
3. compact `linked_neighbors`

Exit criteria:

1. atlas can summarize the graph and tag topology for a scope

### Phase C: Linked navigation

Implement:

1. incoming/outgoing link APIs
2. inspector linked-items board
3. jump-to-linked-item flows

Exit criteria:

1. linked navigation works without raw JSON inspection

### Phase D: TUI search/sort/filter UX

Implement:

1. search mode selector
2. sort selector
3. filter panel or command model
4. scoped search and linked-neighbor search

Exit criteria:

1. search and browse feel like one system

### Phase E: Agent workflows

Implement:

1. explainable atlas/search payloads
2. graph traversal helpers
3. scoped knowledge lookup APIs

Exit criteria:

1. agents can navigate institutional knowledge without bespoke UI logic

## 11) Test Plan

Required test categories:

1. deterministic ordering tests
2. hybrid scoring tests
3. filter/sort interaction tests
4. link navigation tests
5. atlas view rebuild tests
6. v3 interaction tests
7. no-secret-leakage tests for excerpts and summaries

Minimum new suites:

1. `src/tests/test_search_service.py`
2. `src/tests/test_index0_graph_views.py`
3. `src/tests/test_link_navigation.py`
4. extend `src/tests/test_tui_v3_smoke.py`
5. extend `src/tests/test_core_api_services.py`

## 12) Recommended Immediate Next Slice

Implement Phase A first:

1. add `SearchService`
2. define unified result schema
3. support filters + sorting + mode selection
4. thread it into v3 search path without removing current semantic mode support

Completed baseline:

1. `SearchService` exists and is wired into v3
2. unified result schema exists
3. baseline filters + sorting + mode selection exist
4. v3 now uses the unified search path

Recommended next slice:

1. add linked-neighbor and relation-summary service methods
2. expose explicit v3 sort/filter controls instead of implicit command-state only
3. add inspector linked-items board and jump-to-linked-item flows
4. expand atlas views with tag and relation summaries for graph browsing
