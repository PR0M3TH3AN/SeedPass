# Memory Update (2026-03-02)

## TUI v2 mockup parity audit refreshed
- Added a dedicated audit doc: `docs/tui_v2_mockup_gap_audit_2026-03-02.md`.
- Linked the audit from `docs/tui_v2_ui_refresh_plan.md` so future sessions use it as the active parity reference.

## High-impact findings (user-visible)
- Inspector panel currently pre-populates because first entry is auto-selected; this diverges from context-aware mockup behavior.
- Left nav is not yet a true hierarchical tree of fingerprint -> managed-account nodes.
- Layout density and panel proportions still differ from mockup geometry, especially on large displays.
- Reveal/QR pathways exist in code but user runtime still reports non-working `v`/QR behavior in some installs; treat as high-priority runtime validation gap.

## Evidence artifacts to reuse
- Primary runtime evidence: `artifacts/ui_eval/audit_20260302/state_dump.txt`.
- Mockup baseline set: `UI_mockups/PNG/*.png` (all 1854x1080).

## Recommended next implementation slice
1. Remove initial auto-selection and use a neutral inspector state.
2. Implement true left-side hierarchy model.
3. Rework dense header/footer strips to mockup rhythm.
4. Tune spacing/label verbosity for higher effective density before adding new feature surface.

## Plan consolidation (2026-03-02)
- Created `docs/tui_v2_integration_execution_plan_2026-03-02.md` as the consolidated implementation roadmap.
- Captured user-priority requirements: context-aware inspector lifecycle, true fingerprint/managed/agent tree, collapsible sidebar, filter menu replacing always-visible kind toggles, and unified lexical+tag+semantic search.
- Reordered near-term execution toward structure and reliability first (Phases A-C, D, G, H), then semantic integration and final board-fidelity polish.
