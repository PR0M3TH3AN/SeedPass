# TUI v2 Parity Backlog

Status: Active tracking on `beta` (updated 2026-03-01).

This document captures parity learnings and the remaining implementation queue
for Textual TUI v2 versus legacy interactive TUI.

Linked plans:
- `docs/tui_v2_plan.md`
- `docs/tui_v2_parity_checklist.md`
- `docs/tui_v2_cutover_decision.md`

## What We Learned

1. Core shell workflows are stable in TUI v2:
- list/search/filter/detail
- archive/restore
- document edit save/cancel
- graph links + relation filtering + neighbor traversal
- retry/error-recovery flows

2. Security-sensitive parity has improved:
- reveal/QR for `password`, `totp`, `seed`, `managed_account`, `ssh`, `pgp`, `nostr`
- high-risk confirm gates (`reveal confirm`, `qr private confirm`)
- secret-mode clipboard-aware reveal behavior

3. Scale validation now exists for KB-like workloads:
- core sort/tag/search + high-degree graph link stress
- TUI large-index navigation stress

4. Remaining parity is mostly feature-surface breadth, not stability:
- add-entry creation flows in v2
- legacy retrieve/action micro-workflows
- dedicated 2FA board
- settings/profile/nostr operational menus

## Active Build Queue

### Phase A: Add Entry in TUI v2
- [x] Add password creation flow
- [x] Add TOTP creation flow
- [x] Add key/value creation flow
- [x] Add document creation flow
- [x] Add SSH/PGP/Nostr/Seed/Managed Account creation flows
- [x] Add validation and post-create focus/selection behavior

### Phase B: Retrieve/Action Parity
- [x] Add note from selected entry
- [x] Add custom field / hidden field actions
- [x] Edit tags action parity
- [x] Field-level edit parity for non-document kinds
- [x] Document export action
- [x] Nostr QR submenu parity (public/private explicit flows)

### Phase C: 2FA Board Parity
- [x] Dedicated 2FA list board view
- [x] rolling code refresh + remaining timer UI
- [x] secret-mode clipboard behavior in board view
- [x] deterministic/imported split parity and display semantics

### Phase D: Settings/Profile/Nostr Parity
- [x] profile switch/add/remove/list/rename
- [x] secret mode / quick unlock / offline toggles
- [x] inactivity timeout + KDF settings
- [x] relay view/add/remove/reset + sync controls
- [x] checksum verify/generate, import/export db, export totp, parent seed backup/reveal

### Phase E: Release/CI Closure
- [x] Add CI smoke step for `seedpass tui2 --check`
- [x] Extend docs/help parity after each feature landing
- [x] Keep `legacy` fallback path until parity checklist has no high-severity gaps

Release note:
- CI now runs a dedicated `tui2 --check` smoke gate via `scripts/tui2_check_smoke.sh`
  (invoked by `scripts/run_ci_tests.sh`) and in Poetry workflow (`tests.yml`).
- Legacy fallback command/flag paths remain available (`seedpass legacy`,
  `seedpass --legacy-tui`, and `tui2` fallback toggle) while cutover hardening
  continues.

## Execution Notes

- Implement in small vertical slices and check boxes as each slice lands with
  tests.
- Each parity slice must include:
  1) command/keybind discoverability,
  2) service-layer coverage,
  3) Textual interaction tests.
