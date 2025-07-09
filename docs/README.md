# SeedPass Documentation

This directory contains supplementary guides for using SeedPass.

## Quick Example: Get a TOTP Code

Run `seedpass totp <query>` to retrieve a time-based one-time password (TOTP). The
`<query>` can be a label, title, or index. A progress bar shows the remaining
seconds in the current period.

```bash
$ seedpass totp "email"
[##########----------] 15s
Code: 123456
```

## CLI and API Reference

See [advanced_cli.md](advanced_cli.md) for a list of command examples and instructions on running the local API. When starting the API, set `SEEDPASS_CORS_ORIGINS` if you need to allow requests from specific web origins.
