# Secret Scanning

SeedPass uses [Gitleaks](https://github.com/gitleaks/gitleaks) to scan the repository for accidentally committed secrets. The scan runs automatically for pull requests and on a nightly schedule. Any findings will cause the build to fail.

## Suppressing False Positives

If a file or string triggers the scanner but does not contain a real secret, add it to the allowlist in `.gitleaks.toml`.

```toml
[allowlist]
# Ignore specific files
paths = ["path/to/file.txt"]
# Ignore strings that match a regular expression
regexes = ["""dummy_api_key"""]
```

Commit the updated `.gitleaks.toml` to stop future alerts for the allowed items.
