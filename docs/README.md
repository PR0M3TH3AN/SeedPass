# SeedPass Documentation

This directory contains supplementary guides for using SeedPass.

## Quick Example: Get a TOTP Code

Run `seedpass get-code` to retrieve a time-based one-time password (TOTP). A progress bar shows the remaining seconds in the current period.

```bash
$ seedpass get-code --index 0
[##########----------] 15s
Code: 123456
```

See [advanced_cli.md](advanced_cli.md) for a full command reference.
