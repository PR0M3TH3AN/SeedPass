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

See [advanced_cli.md](advanced_cli.md) (future feature set) for details on the upcoming advanced CLI.
