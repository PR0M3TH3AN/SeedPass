# Entry Types and Fields

This document defines the entry kinds supported by SeedPass, shared fields, and kind-specific fields used by the TUI and API.

For graph-link workflows and relationship modeling, see `docs/entry_graph.md`.

## Shared Fields

Every entry kind stores:

- `type`: canonical kind identifier.
- `kind`: kind alias used for backward compatibility.
- `label`: entry title.
- `archived`: boolean archive flag.
- `date_added`: UTC ISO-8601 timestamp set on creation.
- `date_modified`: UTC ISO-8601 timestamp updated on modification.
- `notes`: optional free-form notes.
- `tags`: optional string list.
- `links`: optional relationship list (`target_id`, `relation`, `note`) for graph-style connections between entries.

Internally, SeedPass also tracks `modified_ts` (UNIX timestamp) for deterministic merge conflict resolution.

## Kind-Specific Fields

### `password`

- `length`
- `username`
- `url`
- `policy` (optional password policy overrides)
- `custom_fields` (optional hidden/plain additional fields)

### `totp`

- `index` (for deterministic TOTP) or `secret` (for imported TOTP)
- `period`
- `digits`
- `deterministic`

### `ssh`

- `index` (derivation index)

### `seed`

- `index` (derivation index)
- `word_count`

### `pgp`

- `index` (derivation index)
- `key_type`
- `user_id`

### `nostr`

- `index` (derivation index)

### `key_value`

- `key`
- `value`
- `custom_fields` (optional)

### `managed_account`

- `index` (derivation index)
- `word_count`
- `fingerprint`
- `custom_fields` (optional)

### `document`

- `content`
- `file_type` (extension/type like `txt`, `md`, `py`, `js`, `csv`)
- `custom_fields` (optional)

## TUI Notes

- Add flow: `Main Menu > Add Entry > Document`.
- Document editing uses a built-in line editor:
  - `p` print content
  - `a` append line
  - `i <n>` insert before line
  - `e <n>` edit line
  - `d <n>` delete line
  - `w` save
  - `q` cancel

## API Notes

- Create: `POST /api/v1/entry` with `type=document` (or `kind=document`)
- Update: `PUT /api/v1/entry/{id}` with `content`, `file_type`, `label`, `notes`, `tags`, `archived`
- Read: `GET /api/v1/entry/{id}` returns all stored fields, including `date_added` and `date_modified`
- File import: `POST /api/v1/entry/document/import` with `path` (+ optional `label`, `notes`, `tags`, `archived`)
- File export: `POST /api/v1/entry/{id}/document/export` with optional `path` and `overwrite`
- Link list: `GET /api/v1/entry/{id}/links`
- Link add: `POST /api/v1/entry/{id}/links` with `{ "target_id": 2, "relation": "references", "note": "..." }`
- Link remove: `DELETE /api/v1/entry/{id}/links` with `{ "target_id": 2, "relation": "references" }`

## CLI Notes

- Add directly: `seedpass entry add-document --label "Doc" --content "text" --file-type txt`
- Import from file: `seedpass entry import-document --file ./doc.md`
- Export to file: `seedpass entry export-document --entry-id 42 --out ./exports`
- Agent import: `seedpass -f <fp> agent document-import --file ./doc.md --token <token>`
- Agent export: `seedpass -f <fp> agent document-export --entry-id 42 --out ./exports --token <token>`
- Link add: `seedpass entry link-add --entry-id 1 --target-id 2 --relation references --note "supports deployment"`
- Link list: `seedpass entry links --entry-id 1`
- Link remove: `seedpass entry link-remove --entry-id 1 --target-id 2 --relation references`
