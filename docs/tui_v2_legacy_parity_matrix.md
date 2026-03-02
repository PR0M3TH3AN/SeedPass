# TUI v2 Legacy Parity Matrix

Status: In progress (2026-03-02)  
Branch: `beta`

Purpose: map legacy interactive workflows to Textual TUI v2 equivalents and isolate remaining gaps.

## Summary

- Implemented: core daily workflows are covered in TUI v2 (add/retrieve/search/modify/archive, reveal/QR, 2FA board, settings/profile/relay/sync, export/import/checksum paths).
- Partial: a few legacy menu affordances are represented differently in v2 (palette-first vs nested menus).
- Gaps: remaining high-value gaps are mostly UX-guidance and operational affordances rather than missing core data operations.

## Matrix

| Legacy area/action | Legacy path | TUI v2 path | Status | Notes |
|---|---|---|---|---|
| Add password | Main > Add Entry | `add-password` (palette) | Implemented | Covered by interaction tests. |
| Add TOTP (make/import) | Main > Add Entry > 2FA | `add-totp` (palette) | Implemented | Supports secret/period/digits args. |
| Add SSH | Main > Add Entry | `add-ssh` (palette) | Implemented | |
| Add seed | Main > Add Entry | `add-seed` (palette) | Implemented | |
| Add nostr key | Main > Add Entry | `add-nostr` (palette) | Implemented | |
| Add PGP | Main > Add Entry | `add-pgp` (palette) | Implemented | |
| Add key/value | Main > Add Entry | `add-key-value` (palette) | Implemented | |
| Add managed account entry | Main > Add Entry | `add-managed-account` (palette) | Implemented | |
| Add document | Main > Add Entry | `add-document` (palette) | Implemented | |
| Retrieve entry details | Main > Retrieve Entry | `open <id>`, list select | Implemented | |
| Search entries | Main > Search Entries | `/` search input or `search <q>` | Implemented | |
| List entries | Main > List Entries | center list + pagination | Implemented | |
| Modify entry | Main > Modify Entry | `set-field`, `clear-field`, `notes-*`, `tag-*`, `field-*`, doc editor | Implemented | |
| Archive/unarchive | Retrieve/List actions | `a` key or `archive`/`restore` | Implemented | |
| Entry notes | Entry Actions | `notes-set`, `notes-clear` | Implemented | |
| Entry tags | Entry Actions | `tag-add`, `tag-rm`, `tags-set`, `tags-clear` | Implemented | |
| Custom fields | Entry Actions | `field-add`, `field-rm` | Implemented | |
| Show sensitive reveal | Entry Actions | `v` or `reveal [confirm]` | Implemented | Confirm gates present for high-risk kinds. |
| Show QR | Entry Actions | `g` or `qr [public/private] [confirm]` | Implemented | Includes managed-account + nostr private confirm flow. |
| 2FA codes display | Main > 2FA Codes | `6` toggle board / `2fa-*` commands | Implemented | |
| Link add/remove | N/A or limited | `link-add`, `link-rm` | Implemented | |
| Link traversal | N/A | `l`, `[`, `]`, `o` and `link-*` | Implemented | |
| Profile list/switch/add/remove | Settings > Profiles | `profiles-list`, `profile-switch`, `profile-add`, `profile-remove` | Implemented | |
| Profile rename | Settings > Profiles | `profile-rename` | Implemented | |
| Secret mode toggle | Settings | `setting-secret` | Implemented | |
| Quick unlock toggle | Settings | `setting-quick-unlock` | Implemented | |
| Offline mode toggle | Settings | `setting-offline` | Implemented | |
| Inactivity timeout | Settings | `setting-timeout` | Implemented | |
| KDF mode/iterations | Settings | `setting-kdf-mode`, `setting-kdf-iterations` | Implemented | |
| Relay list/add/remove/reset | Settings > Nostr | `relay-list`, `relay-add`, `relay-rm`, `relay-reset` | Implemented | |
| Sync now/background | Settings > Nostr | `sync-now`, `sync-bg` | Implemented | |
| Verify/generate checksum | Settings | `checksum-verify`, `checksum-update` | Implemented | |
| Export/import database | Settings | `db-export`, `db-import` | Implemented | |
| Export TOTP codes | Settings | `totp-export` | Implemented | |
| Backup/reveal parent seed | Settings | `parent-seed-backup [path] [password]` | Implemented | |
| Stats view | Settings > Stats | `stats` (palette) | Implemented | In-app dashboard in detail pane. |
| First-run onboarding guidance | Startup path/menu guidance | Empty-vault onboarding panel + `onboarding` (alias: `welcome`) + `quickstart` | Implemented | Guided steps for first entry, inspect/reveal, and operations. |
| Display npub | Main utility flow | `npub` (alias: `nostr-pubkey`) | Implemented | Displays active profile npub and QR payload in the sensitive panel. |
| View archived-only list | Settings/List flow | `h` cycle archive scope or `archive-filter <active|all|archived>` | Implemented | Supports active-only/default, all, and archived-only views. |
| Reset Nostr sync state | Settings > Nostr | `nostr-reset-sync-state` | Implemented | Added to TUI v2 palette + tests. |
| Start fresh Nostr namespace | Settings > Nostr | `nostr-fresh-namespace` | Implemented | Added to TUI v2 palette + tests. |
| Load managed-account session | Retrieve managed account action | `managed-load (optional: entry_id)` | Implemented | Added in TUI v2 palette + tests. |
| Exit managed-account session | Main loop when in child profile | `managed-exit` | Implemented | Added in TUI v2 palette + tests. |
| Session visibility | Operational/session affordance | `session-status` + left-pane session lines | Implemented | Shows lock state + managed session state. |
| Lock vault | Operational/session affordance | `lock` | Implemented | Locks session, clears selected view, blocks reveal/open actions. |
| Unlock vault | Operational/session affordance | `unlock <password>` | Implemented | Restores unlocked state; usage + failure paths covered in tests. |

## Prioritized Gap Queue

No active medium/high parity gaps are currently identified in this matrix.
