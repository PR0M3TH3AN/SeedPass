# SeedPass REST API Reference

This guide covers how to start the SeedPass API, authenticate requests, and interact with the available endpoints.

## Starting the API

Run `seedpass api start` from your terminal. The command prints a one‑time token used for authentication:

```bash
$ seedpass api start
API token: abcdef1234567890
```

Keep this token secret. Every request must include it in the `Authorization` header using the `Bearer` scheme.

## Endpoints

- `GET /api/v1/entry?query=<text>` – Search entries matching a query.
- `GET /api/v1/entry/{id}` – Retrieve a single entry by its index.
- `POST /api/v1/entry` – Create a new entry of any supported type.
- `PUT /api/v1/entry/{id}` – Modify an existing entry.
- `PUT /api/v1/config/{key}` – Update a configuration value.
- `POST /api/v1/entry/{id}/archive` – Archive an entry.
- `POST /api/v1/entry/{id}/unarchive` – Unarchive an entry.
- `GET /api/v1/config/{key}` – Return the value for a configuration key.
- `GET /api/v1/fingerprint` – List available seed fingerprints.
- `POST /api/v1/fingerprint` – Add a new seed fingerprint.
- `DELETE /api/v1/fingerprint/{fp}` – Remove a fingerprint.
- `POST /api/v1/fingerprint/select` – Switch the active fingerprint.
- `GET /api/v1/totp/export` – Export all TOTP entries as JSON.
- `GET /api/v1/totp` – Return current TOTP codes and remaining time.
- `GET /api/v1/parent-seed` – Reveal the parent seed or save it with `?file=`.
- `GET /api/v1/nostr/pubkey` – Fetch the Nostr public key for the active seed.
- `POST /api/v1/checksum/verify` – Verify the checksum of the running script.
- `POST /api/v1/checksum/update` – Update the stored script checksum.
- `POST /api/v1/change-password` – Change the master password for the active profile.
- `POST /api/v1/vault/import` – Import a vault backup from a file or path.
- `POST /api/v1/vault/lock` – Lock the vault and clear sensitive data from memory.
- `POST /api/v1/shutdown` – Stop the server gracefully.

**Security Warning:** Accessing `/api/v1/parent-seed` exposes your master seed in plain text. Use it only from a trusted environment.

## Example Requests

Send requests with the token in the header:

```bash
curl -H "Authorization: Bearer <token>" \
     "http://127.0.0.1:8000/api/v1/entry?query=email"
```

### Creating an Entry

`POST /api/v1/entry` accepts a JSON body with at least a `label` field. Set
`type` (or `kind`) to choose the entry variant (`password`, `totp`, `ssh`, `pgp`,
`nostr`, `seed`, `key_value`, or `managed_account`). Additional fields vary by
type:

- **password** – `length`, optional `username`, `url` and `notes`
- **totp** – `secret` or `index`, optional `period`, `digits`, `notes`, `archived`
- **ssh/nostr/seed/managed_account** – `index`, optional `notes`, `archived`
- **pgp** – `index`, `key_type`, `user_id`, optional `notes`, `archived`
- **key_value** – `value`, optional `notes`

Example creating a TOTP entry:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/entry \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"type": "totp", "label": "Email", "secret": "JBSW..."}'
```

### Updating an Entry

Use `PUT /api/v1/entry/{id}` to change fields such as `label`, `username`,
`url`, `notes`, `period`, `digits` or `value` depending on the entry type.

```bash
curl -X PUT http://127.0.0.1:8000/api/v1/entry/1 \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"username": "alice"}'
```

### Updating Configuration

Send a JSON body containing a `value` field to `PUT /api/v1/config/{key}`:

```bash
curl -X PUT http://127.0.0.1:8000/api/v1/config/inactivity_timeout \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"value": 300}'
```

### Switching Fingerprints

Change the active seed profile via `POST /api/v1/fingerprint/select`:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/fingerprint/select \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"fingerprint": "abc123"}'
```

### Enabling CORS

Cross‑origin requests are disabled by default. Set `SEEDPASS_CORS_ORIGINS` to a comma‑separated list of allowed origins before starting the API:

```bash
SEEDPASS_CORS_ORIGINS=http://localhost:3000 seedpass api start
```

Browsers can then call the API from the specified origins, for example using JavaScript:

```javascript
fetch('http://127.0.0.1:8000/api/v1/entry?query=email', {
  headers: { Authorization: 'Bearer <token>' }
});
```

Without CORS enabled, only same‑origin or command‑line tools like `curl` can access the API.
