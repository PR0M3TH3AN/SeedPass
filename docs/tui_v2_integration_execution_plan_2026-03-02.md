# TUI v2 Integration Execution Plan (2026-03-02)

Status: Proposed and ready to execute  
Branch target: `beta`  
Owner: TUI v2 parity track

## 1) Goal

Deliver a mockup-faithful, functionally complete TUI v2 that is visibly reliable, context-aware, and test-gated.

## 2) Consolidated Requirements (From Mockups + User Direction)

1. Left navigation must be a real collapsible hierarchy:
- root fingerprint/seed nodes
- child managed-user nodes
- child agent nodes
- expand/collapse and active-node state

2. Inspector must be context-aware:
- no forced first-row detail on startup
- open/populate only for relevant selection
- clear empty-state when nothing selected

3. Top ribbon must be dense and operational:
- active fingerprint
- loaded profile and managed counts
- entry stats by kind
- active filter summary
- last sync timestamp at right

4. Filtering model:
- kind filters moved behind a compact filter menu
- top ribbon shows active filter summary
- keyboard-first access retained (`f` + palette commands)

5. Unified search:
- single search bar
- exact/field match
- tag match
- semantic vector match
- blended ranking with visible reason indicators

6. Bottom action strip:
- concise global actions
- concise context actions by selected kind
- remove long verbose hint strings from default view

7. Per-kind inspector boards must follow one visual contract:
- password/stored password
- note/document
- totp
- seed/managed account
- ssh/pgp/nostr

8. Sensitive workflows must be obvious and reliable:
- `v` reveal and `g` QR visibly update panel state
- confirm gates for high-risk data remain intact
- hidden/revealed/locked/copied states are explicit

9. Responsive behavior and density:
- good fit at user resolution target (`2256x1504`)
- panel proportions remain usable at smaller terminal sizes
- compact mode keeps core actions and avoids clipping

10. Left panel collapse:
- mouse and keyboard toggle
- state persists in session/profile settings
- expand restores selection and scroll position

## 3) Architecture Decisions

1. Keep terminal font unchanged; improve density in-app.
2. Treat tree node selection as primary context signal for grid and inspector.
3. Use hybrid search abstraction so lexical and semantic are both available.
4. Preserve legacy safety posture for sensitive operations.
5. Keep CLI/API compatibility unchanged while TUI v2 evolves.

## 4) Phased Delivery Plan

## Phase A: Context Model and Selection Lifecycle

Deliver:
1. Remove startup auto-selection.
2. Add neutral inspector empty-state.
3. Make selection transitions deterministic across tree/grid/inspector.

Exit criteria:
1. Startup shows no forced entry detail.
2. Selecting row or tree node populates inspector correctly.
3. No stale inspector content after selection change.

## Phase B: Real Tree Hierarchy + Collapse

Deliver:
1. Tree model for fingerprints, managed users, and agents.
2. Expand/collapse node behavior.
3. Sidebar collapse toggle and persistence.

Exit criteria:
1. Tree reflects real hierarchy.
2. Node selection updates grid scope and ribbon.
3. Collapse/expand works without losing context.

## Phase C: Header/Footer Rebuild

Deliver:
1. Dense top status ribbon with operational stats and sync timestamp.
2. Compact bottom action strip with global and context segments.
3. Remove verbose default hints from main surface.

Exit criteria:
1. Ribbon and strip match mockup interaction rhythm.
2. Information remains readable at target resolution.

## Phase D: Filter Menu and Kind Scope UX

Deliver:
1. Replace visible checkbox row with menu-driven kind filter.
2. Add quick presets (`All`, `Secrets`, `Docs`, `Keys`, `2FA`).
3. Persist active filter state.

Exit criteria:
1. Kind filtering works via menu, hotkey, and palette.
2. Current filter summary is always visible in ribbon.

## Phase E: Unified Hybrid Search (Lexical + Tags + Semantic)

Deliver:
1. Single search surface with mode chips (`Exact`, `Tags`, `Semantic`).
2. Blended ranking and score normalization.
3. Fallback behavior if semantic index unavailable.

Exit criteria:
1. Search returns deterministic merged results.
2. Result rows show reason badges (`title`, `tag`, `semantic`).
3. No regressions in non-semantic environments.

## Phase F: Inspector Board Fidelity Pass

Deliver:
1. Normalize board header/body geometry across kinds.
2. Align button/action placements with mockup direction.
3. Improve notes/tags panel behavior and spacing.

Exit criteria:
1. All major kinds pass visual and interaction checklist.
2. No board has unresolved high-severity gaps.

## Phase G: Sensitive UX Reliability Hardening

Deliver:
1. Strengthen reveal/QR feedback states and transitions.
2. Add runtime checks for installation/runtime variants.
3. Add explicit status and recoverability cues for failures.

Exit criteria:
1. `v`/`g` behavior is consistently visible and test-covered.
2. Confirm-required flows stay enforced.

## Phase H: Responsive and Density Polish

Deliver:
1. Tighten spacing, paddings, and panel proportions.
2. Optimize for `2256x1504` and smaller sizes.
3. Preserve scroll usability in all major panes.

Exit criteria:
1. No clipping or unusable panes in supported viewports.
2. Information density clearly improved over current build.

## 5) Test and Evidence Plan

1. Add/update interaction tests per phase in:
- `src/tests/test_tui_v2_textual_interactions.py`
- `src/tests/test_tui_v2_action_matrix.py`

2. Add targeted tests:
- tree hierarchy navigation and scope changes
- sidebar collapse persistence
- startup no-selection behavior
- filter menu presets and persistence
- hybrid search blending and fallback
- reveal/QR visual state transitions
- responsive compact mode layout integrity

3. Evidence capture after each phase:
- screenshot set against `UI_mockups/PNG/*.png`
- state dump and regression artifact in `artifacts/ui_eval/`

## 6) Priority Order (Immediate)

1. Phase A
2. Phase B
3. Phase C
4. Phase D
5. Phase G
6. Phase H
7. Phase E
8. Phase F

Rationale:
1. Fix context and structure first.
2. Stabilize user trust in reveal/QR before visual fine polish.
3. Integrate semantic search after core layout/control model is stable.

## 7) Definition of Done

1. Mockup gap audit has no High severity items.
2. Critical TUI v2 tests are green in CI gate.
3. User acceptance run confirms:
- context-aware inspector
- hierarchical/collapsible left tree
- compact filter menu
- reliable reveal/QR
- dense readable layout at target resolution.
