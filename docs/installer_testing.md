# Installer Testing

This document describes how SeedPass installer smoke tests are validated across
operating systems and branches (`main`, `beta`).

## CI Workflow

GitHub Actions workflow: `.github/workflows/installer-smoke.yml`

- `pull_request` (reduced matrix):
  - Ubuntu + Windows
  - `beta` branch
  - `tui` mode
- `schedule` + `workflow_dispatch` (full matrix):
  - Ubuntu / macOS / Windows
  - `main` + `beta`
  - `tui` and GUI-capable modes (`both` where supported)

Each job verifies:

1. installer exits successfully
2. launcher is created
3. installed git branch matches requested branch
4. `seedpass --help` runs through launcher
5. installer can be re-run (idempotence smoke check)

## Local Smoke Tests

### Linux / macOS

```bash
bash scripts/installer_smoke_unix.sh beta tui
bash scripts/installer_smoke_unix.sh beta both
```

### Windows (PowerShell)

```powershell
./scripts/installer_smoke_windows.ps1 -Branch beta -Mode tui
./scripts/installer_smoke_windows.ps1 -Branch beta -Mode both
```

The smoke scripts use an isolated temporary home/profile directory so local
user data is not modified.
