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
- `GET /api/v1/config/{key}` – Return the value for a configuration key.
- `GET /api/v1/fingerprint` – List available seed fingerprints.
- `GET /api/v1/nostr/pubkey` – Fetch the Nostr public key for the active seed.
- `POST /api/v1/shutdown` – Stop the server gracefully.

## Example Requests

Send requests with the token in the header:

```bash
curl -H "Authorization: Bearer <token>" \
     "http://127.0.0.1:8000/api/v1/entry?query=email"
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
