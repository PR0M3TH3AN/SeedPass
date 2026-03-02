# TUI v2 UI Refresh Plan (Mockup-Aligned)

Status: Active (2026-03-02)  
Branch target: `beta`  
Primary references: `UI_mockups/PNG/*.png`, `UI_mockups/SeedPass_UI-Board.pdf`

## 1) Purpose

Translate the mockup direction into an implementation-ready, multi-session plan for Textual TUI v2 while preserving SeedPass's green visual identity.

This plan is intentionally detailed so future sessions can continue implementation without re-discovery.

## 2) Design Direction We Are Targeting

From the mockups, the desired direction is:

1. Table-first operations with high information density.
2. Persistent left "seed/account tree" navigation column.
3. Large, contextual lower "inspector board" that changes by selected entry kind.
4. Persistent bottom action strip for discoverability.
5. Strong framed layout (hard borders, segmented panels, explicit labels).
6. Black/neutral structure language, but with SeedPass green theme colors.

## 3) Visual System Contract (Keep Green Theme)

Use the existing TUI v2 palette as baseline (already present in `src/seedpass/tui_v2/app.py`):

- Base background: `#080a0c`
- Panel background: `#0d1114`
- Header/footer background: `#0b0f13`
- Primary text: `#daf2e5`
- Secondary text: `#97b8a6`
- Border default: `#1a3024`
- Border emphasis: `#274533`
- Accent/action: `#2abf75`
- Focus highlight: `#58f29d`

Rules:

1. Keep semantic role colors stable (focus, warning, success, muted).
2. Use contrast through brightness and border weight, not unrelated hues.
3. Keep monochrome mockup geometry and spacing, but render in green palette.

## 4) Information Architecture (Target Layout)

Target screen structure:

1. Top status ribbon:
- fingerprint
- managed users count
- entries count
- active kind/filter
- last sync timestamp

2. Main split:
- Left: seed/account tree + context summary.
- Right:
  - Top: search + filter controls + dense entry table/grid.
  - Bottom: contextual inspector board for selected entry.

3. Bottom action strip:
- Global shortcuts always visible.
- Context shortcuts appended for selected kind and mode.

## 5) Interaction Model Contract

Primary modes:

1. Browse Mode:
- Grid-focused.
- Fast navigation/search/filter/sort.

2. Inspect Mode:
- Inspector board-focused.
- Entry-specific actions (reveal/copy/export/edit/link).

3. Edit Mode:
- Existing document editor/entry mutation mode.

Behavior rules:

1. Selected row always drives inspector board content.
2. Locked vault state must be visible in status ribbon and action strip.
3. Sensitive actions reflect state chips:
- `HIDDEN`, `REVEALED`, `COPIED`, `LOCKED`
4. If no selection exists, inspector shows onboarding or "select entry" guidance.

## 6) Component-Level Spec

### 6.1 Left Navigation Tree

Goal: match mockup's persistent profile/seed hierarchy.

Requirements:

1. Always visible.
2. Shows active profile + managed-account context.
3. Supports keyboard traversal and selection.
4. Selection changes filter context for center grid.

Initial fallback (if full tree data unavailable):

1. Render static grouped sections from currently available services.
2. Keep widget contract stable so backing data can be enriched later.

### 6.2 Top Entry Grid

Goal: table-like view similar to mockups.

Columns (target):

1. Index num
2. Entry num
3. Title
4. Kind
5. Tags (truncated)
6. Date modified
7. Archive/blacklist status

Rules:

1. Compact row density by default.
2. Overflow truncation with consistent ellipsis behavior.
3. Sort indicators shown in header (even if only one active sort initially).
4. Keyboard row selection must stay smooth on large datasets.

### 6.3 Inspector Board (Lower Panel)

Goal: board-style details by entry kind, matching mockup families.

Common board header:

1. Entry label + kind.
2. Modified timestamp.
3. Archive/blacklist status.
4. Index/entry IDs.
5. Right-side primary action button area (`Edit`, etc).

Common board body:

1. Field blocks with labels.
2. Copy/export/reveal controls as command hints/buttons.
3. Notes area.
4. Tags panel (right rail when space permits).

### 6.4 Bottom Action Strip

Goal: persistent discoverability.

Global segment examples:

1. `[S]ettings`
2. `[A]dd Entry`
3. `[C]reate Seed`
4. `[R]emove Seed`
5. `[H]ide/Reveal Sensitive`
6. `[E]xport`
7. `[I]mport`
8. `[B]ackup`

Context segment examples:

1. Password: copy password, copy username, reveal, qr.
2. 2FA: copy code, refresh code, show qr.
3. SSH/PGP: copy public/private, export key.
4. Nostr: copy npub/nsec, show public/private qr.

## 7) Entry-Type Board Templates (Implementation Contract)

Each entry kind gets a formatter/template function returning a structured board text payload.

Template priority order:

1. `password` / `stored_password`
2. `note` / `document`
3. `seed` / `managed_account`
4. `totp`
5. `ssh`
6. `pgp`
7. `nostr`
8. `key_value`
9. fallback generic JSON board

Per-kind minimum fields:

1. Password/stored password:
- password (masked by default), username, url, tags, notes

2. Note/document:
- content preview, tags, notes, file type (document)

3. Seed/managed account:
- seed phrase hidden/reveal state, derivation/index metadata where available, tags, notes

4. TOTP:
- current code, period, digits, secret hidden/reveal, qr support

5. SSH:
- public key, private key hidden/reveal, export hints

6. PGP:
- fingerprint, public key, private key hidden/reveal, export hints

7. Nostr:
- npub, nsec hidden/reveal, public/private qr modes

## 8) Keyboard and Command Mapping Plan

Keep existing keybinds; add stronger discoverability and zone consistency.

Add/confirm mappings:

1. Zone focus:
- `1` left tree
- `2` top grid
- `3` inspector board

2. Mode emphasis:
- `Tab` optional focus advance
- `Shift+Tab` reverse focus (if Textual behavior allows cleanly)

3. Inspector actions:
- keep `v` reveal and `g` qr globally
- add board-level shortcuts to status/action strip text

4. Palette aliases:
- add board/action aliases where needed to mirror strip labels.

## 9) Delivery Plan (Phased Slices)

## Phase 1: Shell Restructure (Layout only)

Deliver:

1. Split right pane into top grid + lower inspector board.
2. Add top status ribbon and bottom action strip scaffolding.
3. Keep existing data behavior unchanged.

Exit criteria:

1. Layout visually resembles mockup structure.
2. Existing interaction tests still pass.
3. No regression in reveal/qr/session behavior.

## Phase 2: Grid Modernization

Deliver:

1. Table-style header row and compact rows.
2. Column alignment/truncation rules.
3. Sort indicator placeholders and active filter badges.

Exit criteria:

1. Large-list navigation remains performant.
2. Paging/search/filter actions remain deterministic.

## Phase 3: Inspector Board Templates (Core Kinds)

Deliver:

1. Board templates for password, note/document, seed, totp.
2. Sensitive-state chips + action hints.
3. Context-aware action strip additions.

Exit criteria:

1. Selected entry shows board instead of raw JSON for covered kinds.
2. Reveal/qr flows are explicit and test-covered.

## Phase 4: Inspector Board Templates (Advanced Kinds)

Deliver:

1. SSH/PGP/Nostr/key_value boards.
2. Copy/export affordance text and command parity hints.
3. Managed-account board treatment.

Exit criteria:

1. All major kinds render purpose-built boards.
2. No loss of existing palette command capability.

## Phase 5: Tree Navigation and Polish

Deliver:

1. Left tree visual and keyboard behavior.
2. Compact vs expanded density mode.
3. Final visual polish against mockups (in green theme).

Exit criteria:

1. Tree + grid + board flow is coherent end-to-end.
2. User walkthrough of top daily workflows feels parity+ with legacy.

## 10) Testing and Quality Gates Per Slice

Mandatory per slice:

1. Update/extend Textual interaction tests in:
- `src/tests/test_tui_v2_textual_interactions.py`
- `src/tests/test_tui_v2_action_matrix.py`

2. Run:
- `poetry run pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py`

3. If app logic paths changed meaningfully, run:
- `scripts/tui2_coverage_gate.sh`

4. Update docs:
- this file
- `docs/tui_v2_legacy_parity_matrix.md`
- `docs/dev_control_center.md` (if priorities shift)

## 11) Non-Goals (for this refresh)

1. Replacing Textual runtime stack.
2. Reworking core service/data model APIs for cosmetic UI concerns.
3. Introducing non-deterministic behavior in entry rendering.
4. Removing legacy TUI fallback before explicit cutover decision.

## 12) Session Handoff Checklist

Before ending any session touching this refresh:

1. Mark phase/slice progress in this document.
2. Record what was implemented and what remains.
3. Add test evidence and known regressions.
4. Append summary to `memory-update.md`.

Current next slice (recommended): **Phase 5 - Interactive tree navigation + final visual polish**.

## 13) Progress Update

### 2026-03-02 - Phase 1 scaffold (initial pass) landed

Implemented in `src/seedpass/tui_v2/app.py`:

1. Added top status ribbon (`#top-ribbon`) with live summary:
- fingerprint
- managed session indicator
- visible entry count
- active kind/archive filters
- lock/session state
- last sync summary

2. Added structural section framing:
- `Entry Grid` heading above center list/search area
- `Inspector Board` heading above right detail area

3. Added persistent bottom action strip (`#action-strip`) with keyboard hint rail.

4. Preserved all existing command behavior and service-layer flows.

Validation:

1. `poetry run pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py`
2. Result: `28 passed`.

Notes:

1. This is a layout/chrome scaffold only; no table/board template conversion yet.
2. Next slice should implement Phase 2 grid modernization without regressing interaction tests.

### 2026-03-02 - Phase 2 grid modernization (initial pass) landed

Implemented in `src/seedpass/tui_v2/app.py`:

1. Upgraded center section heading to a multi-line table scaffold:
- column header row (`Idx`, `Entry`, `Title`, `Kind`, `Meta`, `Arch`)
- sort-indicator placeholder row
- live page/row counts

2. Updated entry list row formatter to aligned, dense table-style rows:
- fixed-width columns for index/entry/title/kind/meta/archive.
- meta column now uses URL or username preview when present.

3. Kept behavior and command flows unchanged (visual/data-presentational slice only).

Validation:

1. `poetry run pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py`
2. Result: `28 passed`.

Next recommended slice:

1. Phase 3 inspector board templates for core kinds (`password`, `document/note`, `seed`, `totp`).

### 2026-03-02 - Phase 3 inspector board templates (core kinds) landed

Implemented in `src/seedpass/tui_v2/app.py`:

1. Replaced raw JSON detail rendering for core kinds with structured board layouts:
- `password` / `stored_password`
- `document` / `note`
- `seed` / `managed_account`
- `totp`

2. Added reusable board helpers:
- entry kind normalization
- common board header (label/kind/id/modified/archived)
- tags and notes normalization

3. Added secure-by-default board copy:
- sensitive values remain hidden in board body
- reveal/QR actions remain the explicit path for sensitive disclosure

4. Kept fallback generic JSON board for non-templated kinds to preserve coverage while templates are expanded.

Validation:

1. `poetry run pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py`
2. Result: `28 passed`.

Next recommended slice:

1. Phase 4 inspector board templates for advanced kinds (`ssh`, `pgp`, `nostr`, `key_value`) and stronger action-strip context hints.

### 2026-03-02 - Phase 4 advanced actions (copy workflow) landed

Implemented in `src/seedpass/tui_v2/app.py`:

1. Added palette command:
- `copy <field> (optional: confirm)`

2. Added kind-aware copy field resolution for:
- `password/stored_password`: `password`, `username`, `url`
- `seed/managed_account`: `seed|phrase`
- `totp`: `code`, `secret`
- `ssh`: `public`, `private`
- `pgp`: `private`, `fingerprint`
- `nostr`: `npub`, `nsec`
- `key_value`: `key`, `value`
- `document/note`: `content|text`

3. Sensitive copy targets now require explicit confirmation (`confirm`) before clipboard action.

4. Updated command reference/help coverage to include `copy`.

Validation:

1. `poetry run pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py`
2. Result: `29 passed`.

Next recommended slice:

1. Extend Phase 4 with explicit file export actions for advanced key kinds (SSH/PGP/Nostr material export paths with confirmation and tests).

### 2026-03-02 - Phase 4 advanced actions (export workflow) landed

Implemented in `src/seedpass/tui_v2/app.py`:

1. Added palette command:
- `export-field <field> <path> (optional: confirm)`

2. Reused kind-aware field resolution from copy workflow and added file export writing:
- supports same kind/field matrix as `copy`.
- writes UTF-8 payloads to absolute or relative paths (relative paths resolve from cwd).

3. Sensitive export targets now require explicit confirmation (`confirm`) before writing.

4. Updated command discoverability/help:
- palette placeholder
- help summary
- full palette reference

Validation:

1. `poetry run pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py`
2. Result: `29 passed`.

Next recommended slice:

1. Continue Phase 5 polish: left tree navigation model + compact/expanded density toggle and final visual alignment pass to mockups.

### 2026-03-02 - Phase 5 polish (density + profile tree scaffold) landed

Implemented in `src/seedpass/tui_v2/app.py`:

1. Added density controls:
- keybind: `d` (toggle compact/comfortable)
- palette: `density <compact|comfortable>`
- top ribbon, left panel, and grid heading now show active density mode

2. Added left-panel profile tree scaffold:
- new `Profiles` section in left panel
- shows known profiles from profile service when available
- marks active fingerprint line

3. Expanded command discoverability:
- palette placeholder/help/reference include `density` command.

Validation:

1. `poetry run pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py`
2. Result: `29 passed`.

Next recommended slice:

1. Continue Phase 5 by adding explicit keyboard navigation inside the left profile tree and wiring profile-selection actions to update active context.

### 2026-03-02 - Phase 5 polish (interactive profile tree navigation) landed

Implemented in `src/seedpass/tui_v2/app.py`:

1. Added keyboard bindings for left profile tree interactions:
- `Up` / `Down`: move profile cursor
- `Ctrl+O`: open/switch to selected profile

2. Added palette command aliases:
- `profile-tree-next`
- `profile-tree-prev`
- `profile-tree-open`

3. Updated left-panel rendering:
- cursor marker (`▶`) and active profile marker (`*`) now render together
- status text confirms selection movement and profile-switch outcomes

4. Wired profile mutation commands to refresh tree state:
- `profile-switch`
- `profile-add`
- `profile-remove`
- `profile-rename`

Validation:

1. `poetry run pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py`
2. Result: `31 passed`.

Next recommended slice:

1. Final visual alignment pass to mockups (spacing, headers, action strip hierarchy) and semantic indicator readability polish.

## 14) Current Status Snapshot

Completed:

1. Phase 1 shell restructure scaffold.
2. Phase 2 grid modernization baseline.
3. Phase 3 core inspector board templates.
4. Phase 4 advanced inspector actions (`copy`, `export-field` with confirm gates).
5. Phase 5 initial polish (`density` controls + profile tree scaffold).
6. Phase 5 interactive profile tree navigation and open/switch behavior.

Remaining (active queue):

1. Final alignment pass to mockup spacing/rhythm and action-strip clarity.
2. Semantic-state indicator readability pass in ribbon/action strip for upcoming dense-status scenarios.
3. Run focused TUI tests and coverage gate after each polish slice.
