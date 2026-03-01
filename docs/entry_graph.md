# Entry Graph Links

SeedPass now supports explicit relationships between entries, so your vault can evolve from tag clusters into a typed knowledge graph.

## Link Model

Every entry can include:

- `links`: list of objects with:
  - `target_id`: target entry index
  - `relation`: link type (for example `references`, `depends_on`, `owned_by`, `derived_from`)
  - `note`: optional free-form context

Example:

```json
{
  "links": [
    { "target_id": 42, "relation": "references", "note": "Used by deploy script" }
  ]
}
```

## CLI Commands

- Add link:
  - `seedpass entry link-add --entry-id 1 --target-id 42 --relation references --note "Used by deploy script"`
- List links:
  - `seedpass entry links --entry-id 1`
- Remove link:
  - `seedpass entry link-remove --entry-id 1 --target-id 42 --relation references`
- Replace full link list:
  - `seedpass entry modify 1 --links-json '[{"target_id":42,"relation":"references","note":"Used by deploy script"}]'`

## API Endpoints

- `GET /api/v1/entry/{id}/links`
- `POST /api/v1/entry/{id}/links`
  - Body: `{ "target_id": 42, "relation": "references", "note": "..." }`
- `DELETE /api/v1/entry/{id}/links`
  - Body: `{ "target_id": 42, "relation": "references" }`
- `PUT /api/v1/entry/{id}` also accepts a full `links` array for replacement.

## Search and Sync Behavior

- Search now matches link metadata (`relation`, `note`) and linked target labels.
- Sync conflict resolution includes `links` in deterministic equal-timestamp union merge, alongside `tags` and `custom_fields`.

## Recommended Conventions

- Keep `relation` values short and consistent (`references`, `depends_on`, `owned_by`, `belongs_to`, `derived_from`).
- Use `note` for human context instead of encoding meaning into long relation strings.
- Use tags for broad grouping, links for explicit semantics.
