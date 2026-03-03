# TUI v2 UI Refresh Plan (Mockup-Aligned)

Status: Active (2026-03-02)  
Branch target: `beta`  
Primary references: `UI_mockups/PNG/*.png`, `UI_mockups/SeedPass_UI-Board.pdf`

Latest audit reference: `docs/tui_v2_mockup_gap_audit_2026-03-02.md`
Execution plan reference: `docs/tui_v2_integration_execution_plan_2026-03-02.md`

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

1. Final alignment pass to mockup spacing/rhythm.
2. Semantic-state indicator readability pass in ribbon/action strip for upcoming dense-status scenarios.
3. Continue board-by-board card/action fidelity polish (Password/Stored Password -> Note/2FA -> SSH/PGP/Nostr).
4. Run focused TUI tests and coverage gate after each polish slice.

## 16) Progress Update (2026-03-02, Slice: Action Rail + Hotkey Reliability)

Implemented:

1. Bottom action strip upgraded to a two-line persistent rail:
- line 1: stable global controls
- line 2: entry-kind contextual controls
2. Status bar upgraded to a two-line presentation for better readability:
- mode/pane + stable shortcut hint
- latest status message
3. Center-pane focus behavior changed to list-first:
- `action_focus_center` now focuses `#entry-list` instead of `#search`
- on launch, focus defaults to `#entry-list`
4. This restores expected immediate hotkey behavior for `v`/`g` without requiring a manual focus fix.
5. Top ribbon readability pass:
- compacted status labels (`FP`, `M`, `E`, `K`, `SEM`, `Sync`)
- semantic mode shortened (`kw|hyb|sem`)
- fingerprint and sync strings truncated for narrow terminals
6. Responsive narrow-screen fallback:
- auto-compact mode when terminal width is narrow
- link context side panel collapses in compact mode to preserve inspector readability
- action strip now signals compact mode (`Compact: links hidden`)
7. Board-fidelity refresh (current slice):
- Password/Stored Password boards now use explicit board titles and refined action/field lines
- Note/Document board now uses explicit board title with clearer preview labeling
- 2FA board action labels clarified (`Copy Code`, `Reveal Secret`, `QR`)
8. Added compact-layout regression test:
- `test_tui2_textual_compact_layout_hides_link_panel_and_can_restore`

Validation:

1. `poetry run pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py`
2. Result: `31 passed`.
3. Added regression coverage:
- `test_tui2_textual_default_focus_keeps_sensitive_hotkeys_active`

## 17) Progress Update (2026-03-02, Slice: SSH/PGP/Nostr Card Fidelity)

Implemented:

1. Inspector header readability tweak:
- changed `Edit: [e]` to `Edit: e` (avoids markup-style ambiguity in Textual render output).
2. SSH board polish:
- explicit `SSH Board` title
- metadata row moved directly under title
- public-key preview line added (truncated for dense layout)
- action rows grouped as public/private operations
3. PGP board polish:
- explicit `PGP Board` title
- metadata-first structure + retained fingerprint prominence
- action rows grouped as public/private operations
4. Nostr board polish:
- explicit `Nostr Board` title
- metadata-first structure + npub/nsec lines
- QR public/private actions shown together
5. Added board-fidelity regression coverage:
- `test_tui2_textual_ssh_pgp_nostr_boards_show_action_fidelity`

Validation:

1. `poetry run pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py`
2. Result: `32 passed`.

Artifacts:

1. `artifacts/ui_eval/current_tui2_after32_ssh.png`
2. `artifacts/ui_eval/current_tui2_after32_pgp.png`
3. `artifacts/ui_eval/current_tui2_after32_nostr.png`

## 18) Progress Update (2026-03-02, Slice: Seed Board Fidelity)

Implemented:

1. Seed-family board specialization:
- `seed` now renders as `BIP-39 Seed Board`
- `managed_account` now renders as `Managed Account Seed Board`
2. Seed metadata fidelity:
- word count now falls back to deriving from `seed_phrase` when `words` is absent
- index metadata remains explicit in the board
3. Seed action affordances aligned to sensitive workflow:
- `Reveal Seed`, `QR Seed`, `Copy Seed(confirm)`, `Export Seed(confirm)`
- clear command hints for confirm-gated copy/export/reveal flows
4. Added board-fidelity regression coverage:
- `test_tui2_textual_seed_and_managed_seed_boards_show_fidelity`

Validation:

1. `poetry run pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py`
2. Result: `33 passed`.

Artifacts:

1. `artifacts/ui_eval/current_tui2_after33_seed.png`
2. `artifacts/ui_eval/current_tui2_after33_managed_seed.png`

## 19) Progress Update (2026-03-02, Slice: Spacing/Rhythm + Compact Action Strip)

Implemented:

1. Layout rhythm tuning:
- top work area increased (`#top-work` from `5fr` to `6fr`)
- inspector area increased (`#right` from `4fr` to `5fr`)
- left rail slightly narrowed (`#left` from `34` to `32`)
- inspector side rail slightly narrowed (`#inspector-side` from `30` to `28`)
2. Compact-mode action-strip readability:
- compact global row now uses shorter labels (`Ctrl+P`, `1/2/3`, `p/n`, `f/h`)
- very narrow widths apply abbreviated context text (`Rev`, `Arch`, `cfm`)
3. Responsive state tracking:
- stores viewport width and adapts action-strip wording accordingly.

Validation:

1. `poetry run pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py`
2. Result: `33 passed`.

Artifacts:

1. `artifacts/ui_eval/current_tui2_after34_password.png`
2. `artifacts/ui_eval/current_tui2_after34_note.png`
3. `artifacts/ui_eval/current_tui2_after34_totp.png`
4. `artifacts/ui_eval/current_tui2_after34_ssh.png`
5. `artifacts/ui_eval/current_tui2_after34_pgp.png`
6. `artifacts/ui_eval/current_tui2_after34_nostr.png`
7. `artifacts/ui_eval/current_tui2_after34_seed.png`
8. `artifacts/ui_eval/current_tui2_after34_managed_seed.png`

## 20) Progress Update (2026-03-02, Slice: Micro-Alignment Tightening)

Implemented:

1. Tightened top-frame rhythm to better mirror mockup structure:
- reduced top-ribbon vertical gap
- removed extra right-panel top gap
2. Increased dense-table feel in center column:
- reduced grid heading height and spacing
- removed quick-jump extra bottom spacing
3. Tightened panel rhythm in left column:
- slightly narrower tree rail
- reduced activity panel height and top gap
4. Improved inspector rhythm:
- removed extra spacing under inspector heading

Validation:

1. `poetry run pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py`
2. Result: `33 passed`.

## 21) Progress Update (2026-03-02, Slice: Header/Action Consistency Sweep)

Implemented:

1. Note/Document board consistency upgrades:
- now includes common metadata line: `Kind | Modified | Archived`
- now includes common ID line: `Index Num* | Entry Num`
2. 2FA board consistency upgrades:
- now includes common metadata line: `Kind | Modified | Archived`
- now includes common ID line: `Index Num* | Entry Num`
3. Added regression coverage:
- `test_tui2_textual_note_and_totp_boards_include_common_metadata`

Validation:

1. `poetry run pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py`
2. Result: `34 passed`.

Artifacts:

1. `artifacts/ui_eval/current_tui2_after35_password.svg`
2. `artifacts/ui_eval/current_tui2_after35_note.svg`
3. `artifacts/ui_eval/current_tui2_after35_totp.svg`
4. `artifacts/ui_eval/current_tui2_after35_ssh.svg`
5. `artifacts/ui_eval/current_tui2_after35_pgp.svg`
6. `artifacts/ui_eval/current_tui2_after35_nostr.svg`
7. `artifacts/ui_eval/current_tui2_after35_seed.svg`
8. `artifacts/ui_eval/current_tui2_after35_managed_seed.svg`

## 22) Progress Update (2026-03-02, Slice: Final Table/Header Micro-Copy)

Implemented:

1. Grid heading copy cleanup:
- removed ambiguous duplicate naming and standardized columns to:
`Sel | Id | Entry# | Label | Kind | Meta | Arch`
2. Board footer action wording normalized across kinds:
- consistent verb-first labels with key hints, e.g.
`Edit (e)`, `Archive (a)`, `Reveal (v)`, `QR (g)`, `Save (Ctrl+S)`, `Cancel (Esc)`.
3. Seed/advanced command hints retained where explicit command forms are needed:
- `copy seed confirm`
- `export-field seed <path> confirm`
- `qr private confirm`

Validation:

1. `poetry run pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py`
2. Result: `34 passed`.

Artifacts:

1. `artifacts/ui_eval/current_tui2_after36_password.svg`
2. `artifacts/ui_eval/current_tui2_after36_note.svg`
3. `artifacts/ui_eval/current_tui2_after36_totp.svg`
4. `artifacts/ui_eval/current_tui2_after36_ssh.svg`
5. `artifacts/ui_eval/current_tui2_after36_pgp.svg`
6. `artifacts/ui_eval/current_tui2_after36_nostr.svg`
7. `artifacts/ui_eval/current_tui2_after36_seed.svg`
8. `artifacts/ui_eval/current_tui2_after36_managed_seed.svg`

## 23) Progress Update (2026-03-02, Slice: 2FA Copy URL Parity Closure)

Implemented:

1. Added first-class 2FA URL copy command:
- `2fa-copy-url <entry_id>`
2. Added TOTP URL support to generic copy flow:
- `copy url confirm` (for selected TOTP entry) now resolves otpauth URI.
3. Surfaced URL copy affordance in 2FA UI text:
- 2FA inspector board action row now includes `Copy URL(confirm)`.
- 2FA board command hint row now includes `2fa-copy-url <entry_id>`.
4. Updated palette discoverability text:
- command palette placeholder, help reference, and quick-help example include `2fa-copy-url`.
5. Added/updated regression coverage:
- extended 2FA board tests to assert:
  - successful URL copy
  - usage and input validation for `2fa-copy-url`
  - board command hint visibility

Validation:

1. `poetry run pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py`
2. Result: `34 passed`.

Strict closeout impact:

1. 2FA board moved from `Open` to `Minor Gap` (functional parity closed; visual polish remains).

## 24) Progress Update (2026-03-02, Slice: Compact Discoverability + Board Polish)

Implemented:

1. Compact-mode notes/tags discoverability upgrade:
- when compact mode collapses the right notes/tags panel, inspector boards now render notes/tags inline for discoverability.
2. Applied inline notes/tags fallback across core boards:
- password/stored_password, note/document, seed/managed_account, totp, ssh, pgp, nostr.
3. Password + Note polish:
- password board now has explicit `Credentials` section.
- note board now uses clearer `Content Preview` heading and flow.
4. Added compact discoverability regression assertions:
- extended `test_tui2_textual_compact_layout_hides_link_panel_and_can_restore` to verify inline notes/tags content.

Validation:

1. `poetry run pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py`
2. Result: `34 passed`.

Artifacts:

1. `artifacts/ui_eval/current_tui2_after38_note_compact.svg`

## 25) Progress Update (2026-03-02, Slice: Viewport Balance Adaptation)

Implemented:

1. Added viewport-height adaptive layout balancing:
- short viewports (`height < 32`): keeps inspector usable and hides activity panel to recover space.
- standard viewports: balanced default (`top-work` / inspector sizing) with activity visible.
- tall viewports (`height >= 52`): increases table density while preserving inspector legibility.
2. Keeps compact-mode width behavior and height behavior coordinated via unified responsive update path.
3. Added viewport-balance regression coverage:
- `test_tui2_textual_viewport_balance_hides_activity_on_short_height`

Validation:

1. `poetry run pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py`
2. Result: `35 passed`.

Artifacts:

1. `artifacts/ui_eval/current_tui2_after39_note_compact_short.svg`
2. `artifacts/ui_eval/current_tui2_after39_note_standard.svg`

## 26) Progress Update (2026-03-02, Slice: Typography/Icon Polish)

Implemented:

1. Added consistent kind icons in inspector board titles/headers for stronger visual scanning:
- password, note/document, 2FA, seed/managed seed, SSH, PGP, Nostr now include their kind icon in board title lines.
2. Applied icon-enhanced shared entry-header format for template-based boards.
3. Preserved command and behavior parity while improving visual hierarchy.

Validation:

1. `poetry run pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py`
2. Result: `35 passed`.

Artifacts:

1. `artifacts/ui_eval/current_tui2_after40_password.svg`
2. `artifacts/ui_eval/current_tui2_after40_note.svg`
3. `artifacts/ui_eval/current_tui2_after40_totp.svg`
4. `artifacts/ui_eval/current_tui2_after40_ssh.svg`
5. `artifacts/ui_eval/current_tui2_after40_pgp.svg`
6. `artifacts/ui_eval/current_tui2_after40_nostr.svg`
7. `artifacts/ui_eval/current_tui2_after40_seed.svg`
8. `artifacts/ui_eval/current_tui2_after40_managed_seed.svg`

## 15) Mockup Board Parity Audit (2026-03-02)

Source set reviewed:

1. `UI_mockups/PNG/UI Board.png`
2. `UI_mockups/PNG/Password Board.png`
3. `UI_mockups/PNG/Stored Password Board.png`
4. `UI_mockups/PNG/Note Board.png`
5. `UI_mockups/PNG/2FA Board.png`
6. `UI_mockups/PNG/BIP-39 Seed Board.png`
7. `UI_mockups/PNG/SSH Board.png`
8. `UI_mockups/PNG/PGP Board.png`
9. `UI_mockups/PNG/Nostr Board.png`

### 15.1 Shared Layout Contract (from all mockups)

Expected:

1. Dense table-first upper region with always-visible rows and explicit separators.
2. Persistent left hierarchy tree with compact, high-signal metadata.
3. Lower inspector with:
- shared header row (`label`, `kind`, `modified`, blacklist/archive, index/entry)
- field cards
- right-side secondary card (tags/notes/links/sensitive)
4. Bottom action rail with stable global actions + contextual actions.

Current status:

1. Implemented in structure, but still needs spacing/density tuning to keep both:
- sufficient table rows visible
- full inspector card content visible in same viewport

### 15.2 Board-by-Board Functional + Layout Parity

| Mockup board | Required field/layout traits | Required actions | TUI v2 status |
|---|---|---|---|
| UI Board | Dense table, left tree, bottom rail | search/filter/paging/navigation | Minor Gap |
| Password | password/username/url/tags + notes side panel | copy password, create new, edit, reveal/qr | Minor Gap |
| Stored Password | password/username/url/tags + notes side panel | copy password, edit, reveal/qr | Minor Gap |
| Note | large content area + tags side card | edit/save/cancel/export | Minor Gap |
| 2FA | code field + URL field + notes/tags side card | copy code, copy URL, reveal/qr, 2FA board | Done |
| BIP-39 Seed | seed field + notes + tags side card | reveal/confirm, qr, copy/export with confirm | Done |
| SSH | public/private rows + notes/tags side card | copy public/private, export public/private, reveal private | Done |
| PGP | public/private rows + notes/tags side card | copy/export public/private, reveal private | Done |
| Nostr | npub/nsec rows + notes/tags side card | copy npub/nsec, qr public/private, reveal nsec | Done |

### 15.3 Closeout Status Definitions (Strict)

1. `Done`: matching layout and actions with no user-visible parity gap in normal viewport.
2. `Minor Gap`: core behaviors present; remaining differences are visual rhythm/density or secondary affordance polish.
3. `Open`: missing required interaction from mockup contract.

### 15.4 Strict Closeout Notes (2026-03-02)

1. `UI Board` -> Minor Gap:
- structure is correct (left tree + table + inspector + action rail), but table density and lower board visibility balance still need final tuning.
2. `Password/Stored Password` -> Minor Gap:
- core actions and fields are present; remaining gap is closer card geometry fidelity to mockup.
3. `Note` -> Minor Gap:
- edit/save/export flow is complete; remaining gap is larger content-card visual weighting compared to mockup.
4. `2FA` -> Done:
- code/URL copy, reveal, QR, and board workflows are now first-class and discoverable.
5. `BIP-39 Seed` -> Done:
- reveal/QR/copy/export confirm workflows are present with board-level affordances.
6. `SSH/PGP/Nostr` -> Done:
- required copy/export/reveal/QR workflows are present with explicit board action affordances.

### 15.5 Current Priority Gap Order (derived from strict closeout)

1. Keep strict `Open` count at zero by preserving 2FA copy-URL parity.
2. Final visual card/rhythm pass for remaining `Minor Gap` boards (`UI Board`, `Password`, `Stored Password`, `Note`).
3. Final action-rail wording polish to match mockup verbs.

### 15.6 Immediate Next Slice (strict closeout coupled)

1. Final card geometry pass for Password/Stored Password/Note.
2. Final UI-board density pass (table rows + lower inspector balance).
3. Final action-strip verb/microcopy polish.
4. Re-run focused suite and capture `after41` artifacts.

## 27) Progress Update (2026-03-02, Slice: Strict Closeout Scoring Pass)

Scoring method:

1. `Done`: no user-visible functional parity gap and mockup-consistent action discoverability in normal viewport.
2. `Minor Gap`: functional parity met, but visual/rhythm mismatch remains.
3. `Open`: required interaction missing.

Current strict closeout scoreboard:

1. `Done` (5/9): `2FA`, `BIP-39 Seed`, `SSH`, `PGP`, `Nostr`.
2. `Minor Gap` (4/9): `UI Board`, `Password`, `Stored Password`, `Note`.
3. `Open` (0/9).

Evidence basis:

1. Focused validation gate: `35 passed` in current run set.
2. Artifact set: `artifacts/ui_eval/current_tui2_after40_*.svg`.
3. Dedicated parity regressions in `src/tests/test_tui_v2_textual_interactions.py` for:
- default hotkey focus
- compact discoverability
- board fidelity (`SSH/PGP/Nostr`, `Seed/Managed Seed`, `Note/2FA metadata`)
- viewport balance behavior

## 28) Detailed UX Audit (2026-03-02, Pre-Implementation Writeup)

Scope:

1. Compare current TUI v2 runtime states against mockup set in `UI_mockups/PNG/*.png`.
2. Focus on:
- context-aware inspector behavior
- left tree structure fidelity
- per-board layout transitions and function-driven UI changes

Evidence captured:

1. Runtime state dump:
- `artifacts/ui_eval/audit_20260302/state_dump.txt`
2. Board screenshots (vector snapshots):
- `artifacts/ui_eval/audit_20260302/*.svg`

### 28.1 Key User-Reported Concerns: Validation

1. Concern: inspector panel appears open/populated all the time.
- Confirmed behavior in current v2:
  - first row is auto-selected on load (`Selected: #0 ...` in state dump),
  - inspector is therefore always populated by design.
- Mockup intent:
  - inspector content is contextual and should feel state-driven, not always-active by default.
- Status:
  - Functional but not matching UX intent; should be revised to delayed/populated-on-explicit-selection behavior.

2. Concern: left tree does not reflect fingerprint/managed-account hierarchy.
- Confirmed behavior in current v2:
  - left panel shows profile list scaffold with shallow pseudo-tree lines from profile fingerprints.
  - managed accounts are not rendered as child nodes in this structure.
- Mockup intent:
  - deep hierarchical seed/account tree with clear parent-child grouping.
- Status:
  - Partial scaffold only; structural data model + renderer need expansion.

### 28.2 Board-by-Board Layout/Function Transition Audit

UI Board (global layout):

1. Present:
- top ribbon, left rail, center grid, lower inspector, bottom action strip.
2. Missing vs mockup:
- tree depth and semantic grouping on left.
- denser table row packing with richer column semantics (mockup includes blacklist/date emphasis).
- true “inspect mode” transition behavior (instead of always-populated inspector at startup).

Password / Stored Password:

1. Present:
- board titles, metadata, credentials rows, action affordances, right notes/tags side panel.
2. Gaps:
- visual card geometry still less segmented than mockup (mockup uses stronger field-card framing and right notes dominance).
- “create new”/copy controls are textual chips, not distinct button blocks with stronger visual separation.

Note Board:

1. Present:
- content preview, metadata, edit/export actions, notes/tags panel, compact inline fallback.
2. Gaps:
- mockup shows stronger large-content card emphasis with clearer right notes pane ratio.
- current board remains text-first and less panelized.

2FA Board:

1. Present:
- copy code, copy URL, reveal, QR, dedicated 2FA board commands and hints.
2. Gaps:
- visual treatment of URL/code cards not yet equivalent to mockup’s framed field blocks.

BIP-39 Seed Board:

1. Present:
- reveal/QR/copy/export confirm paths, word-count/index metadata, managed vs non-managed board variants.
2. Gaps:
- card visual hierarchy still lighter than mockup’s framed block style.

SSH / PGP / Nostr:

1. Present:
- required copy/export/reveal/QR action coverage and metadata lines.
2. Gaps:
- action chips and field block segmentation still not as bold as mockup button/card composition.

### 28.3 Layout State Changes (Function-Driven) vs Mockup Expectations

Current implemented state transitions:

1. Selection changes board content.
2. Compact width hides side notes/links panel and now inlines notes/tags.
3. Short height hides activity panel to preserve core content area.
4. 2FA board toggles into dedicated live-code table view.

Still needed to match mockup behavior intent:

1. Startup with no forced selection state (or a true neutral “select entry” inspect state).
2. Explicit browse-mode vs inspect-mode layout emphasis:
- browse: denser table, reduced inspector prominence
- inspect: fuller lower board prominence after explicit open/select action
3. Left tree deep hierarchy with managed-account child nodes and clearer expand/collapse semantics.

### 28.4 Font Size Request Constraint

1. Terminal font size itself is controlled by the terminal emulator, not Textual app CSS.
2. App-side equivalent for “smaller font feel” is:
- tighter spacing/margins/heights,
- shorter labels,
- denser row/column presentation,
- reduced decorative padding.
3. Next implementation slices should target this density path to effectively fit more content per viewport.

## 29) Progress Update (2026-03-03, Slice: Password/Stored Password/Note Card Geometry)

Completed:

1. Password and Stored Password inspector boards now use stronger card sections:
- `Credentials`
- `Quick Actions`
2. Note/Document board now uses the same card section framing:
- `Content`
- `Quick Actions`
3. Increased note preview payload from 120 to 180 chars for better content-card parity in standard density.

Code references:

1. `src/seedpass/tui_v2/app.py` (`_board_card`, password/stored_password board, note/document board)

Regression coverage:

1. Updated note board metadata test to assert card framing.
2. Added password board card-section regression test.

Validation:

1. `poetry run pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py`
2. Result: `57 passed`.

Remaining strict-closeout slice order unchanged:

1. Final UI-board density pass (table rows + lower inspector balance)
2. Final action-strip verb/microcopy polish

## 30) Progress Update (2026-03-03, Slice: UI-Board Density Rebalance)

Completed:

1. Dense/high-res layout now rebalances vertical space by context:
- Idle (no selected entry, no editor, no 2FA board): `top-work=9fr`, `right=3fr`
- Active inspect/edit/2FA: `top-work=8fr`, `right=4fr`
2. Added explicit layout rebalance hook so selection and pane-mode transitions re-apply split without requiring window resize.
3. Rebalance path wired through:
- page render transitions (empty/non-empty)
- entry selection/open flow
- right-pane mode switches (view/edit/2FA)

Code references:

1. `src/seedpass/tui_v2/app.py` (`_update_responsive_layout`, `_refresh_layout_balance`, `_set_right_pane_mode`, `_render_current_page`, `_show_entry`)

Regression coverage:

1. Added dense-mode split behavior test:
- `test_tui2_textual_hires_density_rebalances_idle_vs_selected`

Validation:

1. `poetry run pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py`
2. Result: `58 passed`.

Remaining strict-closeout slice:

1. Final action-strip verb/microcopy polish.

## 31) Progress Update (2026-03-03, Slice: Action-Strip Verb/Microcopy Polish)

Completed:

1. Context row wording standardized to verb-first labels with key hints:
- `Reveal (v)`
- `QR (g)`
- `Edit (e)` / `Edit Doc (e)`
- `Archive (a)`
- `Save (Ctrl+S)`
- `2FA Board (6)`
2. Managed account row now retains explicit session controls while matching the same style:
- `managed-load`
- `managed-exit`
- plus reveal/qr/edit/archive with key hints.
3. Click routing remains compatible after copy update:
- row-2 parser now recognizes both symbol-led and verb-led tokens (`v`/`Reveal`, `g`/`QR`, etc.).

Code references:

1. `src/seedpass/tui_v2/app.py` (`_update_action_strip`, `_action_strip_context_action`)

Regression coverage:

1. Updated action-strip click + context-update tests to assert verb-led labels.

Validation:

1. `poetry run pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py`
2. Result: `58 passed`.

## 32) Progress Update (2026-03-03, Slice: Universal Card Framing)

Completed:

1. Extended `_board_card` framing to all remaining inspector boards:
   - TOTP: `Parameters` (period/digits/code/secret) + `Quick Actions`
   - SSH: `Keys` (public/private) + `Quick Actions`
   - PGP: `Keys` (fingerprint/public/private) + `Quick Actions`
   - Nostr: `Keys` (npub/nsec) + `Quick Actions`
   - Seed/Managed Account: `Seed Info` (phrase/word count/index) + `Quick Actions`
2. All boards now use consistent card-section visual language matching the Password/Note treatment from Slice 29.

Code references:

1. `src/seedpass/tui_v2/app.py` (TOTP, SSH, PGP, Nostr, Seed board sections)

Regression coverage:

1. Updated SSH/PGP/Nostr board test to assert `+- Keys` and `+- Quick Actions` card framing.
2. Updated Seed/Managed Seed board test to assert `+- Seed Info` and `+- Quick Actions` card framing.
3. Updated TOTP board test to assert `+- Parameters` and `+- Quick Actions` card framing.

Validation:

1. `poetry run pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py`
2. Result: `58 passed`.

Strict closeout impact:

1. All 9 board types now have consistent card-section framing.
2. SSH/PGP/Nostr/Seed boards moved from visual-gap to card-parity with Password/Note.

## 33) Progress Update (2026-03-03, Slice: Board Density Tightening)

Completed:

1. Removed redundant plain-text section headers above card frames:
   - "Login Fields", "Document Fields", "2FA Fields", "Seed Fields", "Key Material", "Operations"
   - Card titles (`Credentials`, `Content`, `Parameters`, `Seed Info`, `Keys`, `Quick Actions`) are self-descriptive.
2. Removed "Compact: Notes/Tags shown inline." noise line from compact mode boards.
3. Capped note/document preview length from 180 to 100 chars to prevent oversized Content cards.

Density improvement:

1. Password board: ~21 lines -> 17 lines (-4 lines per board).
2. All boards save 2-3 lines from removed section headers.
3. Note board Content card width reduced by ~45%.

Code references:

1. `src/seedpass/tui_v2/app.py` (all board sections + `_notes_tags_panel_hint`)

Regression coverage:

1. Updated assertions from section headers to card-frame prefixes.
2. Removed "Compact:" noise assertion.

Validation:

1. `poetry run pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py`
2. Result: `58 passed`.

## 34) Progress Update (2026-03-03, Slice: Action Strip + Hint Line Tightening)

Completed:

1. Normal-mode global action strip now uses verb-first labels with key hints:
   - `Settings (Shift+S)`, `Add (Shift+A)`, `Seed+ (Shift+C)`, etc.
   - Added `Cmd (Ctrl+P)` to normal mode for discoverability parity with compact/dense modes.
2. Shortened Seed board Actions hint:
   - Before: `copy seed confirm | export-field seed <path> confirm`
   - After: `Copy Seed (confirm) | Export (confirm)`
3. Shortened TOTP board Actions hint:
   - Before: `2fa-copy <id> | 2fa-copy-url <id>`
   - After: `Copy Code (Ctrl+P) | Copy URL (Ctrl+P)`
4. Action hints now consistently use user-facing verbs instead of raw palette commands.

Validation:

1. `poetry run pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py`
2. Result: `58 passed`.

## 35) Progress Update (2026-03-03, Slice: Final Micro-Polish)

Completed:

1. Added max-width cap (72 chars) to `_board_card` renderer:
   - Content cards no longer stretch across the full viewport.
   - Long rows are truncated with ellipsis character.
   - Note board max line width reduced from ~112 to 76 chars.
2. Capitalized Nostr action hint:
   - Before: `qr private confirm`
   - After: `QR Private (confirm)`
3. Compact mode global strip now uses verb-first labels:
   - Before: `S Settings  A Add  C Create Seed  R Remove Seed  H Hide/Reveal  E Export  I Import  B Backup  Ctrl+P Cmd  Compact`
   - After: `Settings (S)  Add (A)  Seed+ (C)  Seed- (R)  Reveal (H)  Export (E)  Import (I)  Backup (B)  Cmd (Ctrl+P)`

Validation:

1. `poetry run pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py`
2. Result: `58 passed`.

## 36) Progress Update (2026-03-03, Slice: UX Bug Fixes from Walkthrough)

Completed:

1. Fixed `open <non-existent-id>` showing broken empty board:
   - Now checks for empty dict (not just None) from retrieve_entry.
   - Shows clear "Entry #N not found" message in inspector.
   - Clears selection state so action strip doesn't show stale context.
2. Fixed tree navigation silently ignoring commands when focus is on wrong pane:
   - `profile-tree-next`, `profile-tree-prev`, `profile-tree-open` now show
     "Focus left pane first (press 1)" instead of silently returning.
   - Also shows "Sidebar is collapsed. Press Ctrl+B to expand." when sidebar is collapsed.

Regression coverage:

1. Added `test_tui2_textual_open_nonexistent_entry_shows_not_found`.
2. Added `test_tui2_textual_tree_nav_feedback_when_wrong_pane`.

Validation:

1. `poetry run pytest -q src/tests/test_tui_v2_textual_interactions.py src/tests/test_tui_v2_action_matrix.py`
2. Result: `60 passed`.
