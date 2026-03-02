# TUI v2 Mockup Gap Audit (2026-03-02)

Status: Active  
Scope: visual and interaction parity between `UI_mockups/PNG/*.png` and current Textual TUI v2 runtime

## Sources Compared

1. Mockups:
- `UI_mockups/PNG/UI Board.png`
- `UI_mockups/PNG/Password Board.png`
- `UI_mockups/PNG/Stored Password Board.png`
- `UI_mockups/PNG/Note Board.png`
- `UI_mockups/PNG/2FA Board.png`
- `UI_mockups/PNG/BIP-39 Seed Board.png`
- `UI_mockups/PNG/SSH Board.png`
- `UI_mockups/PNG/PGP Board.png`
- `UI_mockups/PNG/Nostr Board.png`

2. Current v2 evidence:
- `artifacts/ui_eval/audit_20260302/state_dump.txt`
- current code path: `src/seedpass/tui_v2/app.py`
- user runtime screenshot (provided in thread)

3. Mockup size baseline:
- all mockups are `1854x1080` (`identify UI_mockups/PNG/*.png`)

## Executive Status

Overall parity to mockup direction is partial and not release-grade for UI fidelity.

Estimated alignment:
1. Layout shell parity: ~65%
2. Interaction model parity: ~55%
3. Board visual/content parity: ~70%
4. Responsive behavior parity: ~45%

Main blockers:
1. Inspector is effectively always populated because the first row auto-selects on render.
2. Left navigation is not a real hierarchical tree of fingerprints -> managed accounts.
3. Header/footer rhythm and panel proportions do not match mockup geometry.
4. Dense table readability is limited by current spacing and border treatment.

## Confirmed Mismatches

## 1) Inspector Lifecycle and Context Awareness

Mockup expectation:
1. Lower board is contextual and meaningfully state-driven.
2. Empty states should appear only when no relevant item is selected.
3. Panel emphasis should shift by active context (entry type, mode, and selection).

Current behavior:
1. Initial render auto-selects first entry (`Selected: #0 AIIT`) so inspector loads immediately.
2. Side/notes panel is persistently present in normal layout.
3. Link/secret areas are rendered as static regions with status text.

Evidence:
1. `artifacts/ui_eval/audit_20260302/state_dump.txt:6`
2. `artifacts/ui_eval/audit_20260302/state_dump.txt:35`
3. `artifacts/ui_eval/audit_20260302/state_dump.txt:48`
4. `artifacts/ui_eval/audit_20260302/state_dump.txt:58`
5. `src/seedpass/tui_v2/app.py:1134`

Gap severity: High

## 2) Left Tree Hierarchy Depth

Mockup expectation:
1. A clear multi-level tree with top-level seeds/fingerprints and child managed accounts.
2. Expand/collapse semantics and active branch clarity.
3. Tree as a primary navigation rail, not only summary text.

Current behavior:
1. Left pane prints a profile list block with pseudo-tree glyphs.
2. No concrete managed-account child nodes tied to each fingerprint branch.
3. Branch semantics are visually ambiguous (single selected marker plus list lines).

Evidence:
1. `artifacts/ui_eval/audit_20260302/state_dump.txt:15`
2. `artifacts/ui_eval/audit_20260302/state_dump.txt:17`
3. `artifacts/ui_eval/audit_20260302/state_dump.txt:18`
4. `src/seedpass/tui_v2/app.py:961`

Gap severity: High

## 3) Header and Footer Structure

Mockup expectation:
1. Top ribbon packs operational status into one dense strip: fingerprint, managed users, entries, filter, sync.
2. Bottom strip is simple operator actions with high scanability.

Current behavior:
1. Top status details are split across multiple lines in the left pane, not in a single dense ribbon.
2. Bottom action strip is text-heavy and wraps into long hint sequences.
3. Geometry and spacing diverge from the mockup’s rigid row framing.

Evidence:
1. `artifacts/ui_eval/audit_20260302/state_dump.txt:3`
2. `artifacts/ui_eval/audit_20260302/state_dump.txt:22`
3. `artifacts/ui_eval/audit_20260302/state_dump.txt:30`
4. `src/seedpass/tui_v2/app.py:724`

Gap severity: Medium

## 4) Entry Grid Density and Legibility

Mockup expectation:
1. Table columns are tight but consistently aligned.
2. Dense data view still preserves strong hierarchy and line separation.
3. Search bar and table header rows are visually integrated.

Current behavior:
1. Current grid is compact but still visually looser than the mockups.
2. Spacing and separators in real terminal output can feel sparse or noisy depending on viewport.
3. User screenshot shows empty-looking cells and over-emphasized border blocks.

Evidence:
1. `artifacts/ui_eval/audit_20260302/state_dump.txt:27`
2. `src/seedpass/tui_v2/app.py:1025`
3. user screenshot attached in thread (2256x1504 display; large pane but low information density)

Gap severity: Medium

## 5) Kind-Specific Inspector Boards

Mockup expectation:
1. Each kind board follows a common skeleton with strong field blocks.
2. Notes/tags side rail appears as a stable right section.
3. Sensitive boards present explicit reveal/copy/export affordances in a consistent row.

Current behavior:
1. Most board templates are present and functionally wired (`password`, `stored_password`, `document`, `totp`, `seed`, `ssh`, `pgp`, `nostr`).
2. Boards are currently text-driven; they do not fully match mockup panel geometry and control placement.
3. QR/reveal behavior is command-first; visual call-to-action is weaker than mockup buttons.

Evidence:
1. `artifacts/ui_eval/audit_20260302/state_dump.txt:62`
2. `artifacts/ui_eval/audit_20260302/state_dump.txt:149`
3. `artifacts/ui_eval/audit_20260302/state_dump.txt:178`
4. `artifacts/ui_eval/audit_20260302/state_dump.txt:206`
5. `artifacts/ui_eval/audit_20260302/state_dump.txt:265`
6. `src/seedpass/tui_v2/app.py:1244`

Gap severity: Medium

## 6) Responsive Behavior and Screen Fit

Mockup expectation:
1. Stable composition at standard laptop and ultrawide sizes.
2. Scroll and panel collapse rules that preserve operator context.

Current behavior:
1. Compact mode triggers at terminal width < 150 columns (`_compact_layout`).
2. In compact mode, side panel is hidden and notes/tags move inline.
3. This is useful fallback behavior, but breakpoint and proportion strategy still need tuning for large/high-DPI terminals.

Evidence:
1. `src/seedpass/tui_v2/app.py:855`
2. `artifacts/ui_eval/audit_20260302/state_dump.txt:294`
3. `artifacts/ui_eval/audit_20260302/state_dump.txt:334`

Gap severity: Medium

## 7) Reveal/QR UX (as perceived by user)

Mockup expectation:
1. Reveal and QR should feel immediate and obvious from board controls.
2. Sensitive panel state should communicate exactly what happened.

Current behavior:
1. Implementation path exists for reveal and QR and includes confirm gates.
2. User-reported behavior indicates reveal key not producing expected visual result in their install.
3. This suggests a runtime/render/state issue still exists in at least one install path.

Evidence:
1. `src/seedpass/tui_v2/app.py:311`
2. `src/seedpass/tui_v2/app.py:312`
3. `src/seedpass/tui_v2/app.py:2026`
4. user screenshot and report in thread

Gap severity: High (because user-visible and trust-impacting)

## Detailed Board-by-Board Comparison

## UI Board

Matched:
1. Three-zone concept exists (left nav, table, inspector zone).
2. Global/search/filter controls exist.

Missing/Off:
1. Tree depth and true hierarchy behavior.
2. Dense top ribbon shape.
3. Footer action strip simplicity and visual weight.
4. Inspector should not pre-populate by default.

## Password / Stored Password

Matched:
1. Core fields and actions exist.
2. Notes/tags are available.

Missing/Off:
1. Geometry differs from mockup button block layout.
2. Visual CTA buttons are weaker than mockup-style controls.
3. Sensitive feedback placement not as clear.

## Note

Matched:
1. Note content and tags/notes context are present.

Missing/Off:
1. Scroll area framing and right-side tag rail are less structured than mockup.
2. Edit affordance placement differs.

## 2FA

Matched:
1. 2FA board, code/secret/QR paths implemented.

Missing/Off:
1. Direct board-level action clarity (copy code/url) is less visual.
2. Timing/code emphasis differs from mockup board design.

## BIP-39 Seed, SSH, PGP, Nostr

Matched:
1. Per-kind data and reveal/export/copy action paths exist.

Missing/Off:
1. Board framing and button hierarchy diverge.
2. QR and reveal state transitions are too subtle visually.

## Prioritized Fix Queue (Before More Feature Surface Area)

1. Stop auto-selecting first row on initial render; show neutral inspector empty state.
2. Build real left hierarchical tree model:
- root fingerprint nodes
- child managed account nodes
- clear active branch highlighting
3. Rework top ribbon into one dense status row.
4. Simplify bottom action strip to mockup-style short labels.
5. Strengthen inspector context transitions:
- hidden when no selection
- board-specific widgets when selected
- clearer sensitive panel transitions for `v`/`g`
6. Tune spacing/density for large displays:
- tighter vertical padding
- narrower borders
- reduced label verbosity

## Font Size and Density Note

Terminal font size is controlled by the terminal emulator, not by Textual app CSS in a reliable cross-terminal way.

To fit more content on screen in-app, we should treat this as a density problem:
1. reduce widget padding/margins
2. shorten labels
3. shrink fixed panel heights
4. increase rows per table viewport
5. collapse secondary hints behind `?`/help overlay

## Recommendation for Next Implementation Slice

Do not add new feature surface first.  
Start with UX parity slice focused on:
1. selection/inspector lifecycle
2. real left tree hierarchy
3. density and strip simplification

Then re-run screenshot audit against all 9 mockups and update this doc with pass/fail per board.
