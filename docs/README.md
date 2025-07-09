# SeedPass Documentation

This directory contains supplementary guides for using SeedPass.

## Quick Example: Get a TOTP Code

Run `seedpass entry get <query>` to retrieve a time-based one-time password (TOTP).
The `<query>` can be a label, title, or index. A progress bar shows the remaining
seconds in the current period.

```bash
$ seedpass entry get "email"
[##########----------] 15s
Code: 123456
```

To show all stored TOTP codes with their countdown timers, run:

```bash
$ seedpass entry totp-codes
```

## CLI and API Reference

See [advanced_cli.md](advanced_cli.md) for a list of command examples. Detailed information about the REST API is available in [api_reference.md](api_reference.md). When starting the API, set `SEEDPASS_CORS_ORIGINS` if you need to allow requests from specific web origins.
