# TUI v2 Large-Vault Validation

> **Legacy (Python implementation).** This document describes the Python version, which retires to `legacy/` after the TypeScript cutover ([PR #989](https://github.com/PR0M3TH3AN/SeedPass/pull/989)). The TypeScript interactive mode follows the classic v1 menus; TUI v2/v3, index0/atlas, and semantic search were not ported. Kept as historical record.

Status: Added on `beta` (March 1, 2026).

This document defines a deterministic, CI-like validation pass for TUI v2 behavior at large vault sizes.

## What Is Validated

- Pagination behavior across large deterministic datasets.
- Detail preview truncation behavior for large document content.

## Test Module

- `src/tests/test_tui_v2_large_vault_validation.py`

## Deterministic Data Profile

- Standard profile: `10,000` entries.
- Stress profile: `50,000` entries (`--stress`).
- Labels are deterministic (`Entry-000000` style).

## Runtime Thresholds

Pagination scan budget (wall-clock for scan loop):
- `10,000` rows: `<= 2.0s`
- `50,000` rows: `<= 8.0s`

Detail truncation checks:
- Confirms bounded preview behavior at large content sizes.

## Commands

Standard CI-like run:

```bash
.venv/bin/python -m pytest -q src/tests/test_tui_v2_large_vault_validation.py
```

Extended stress run:

```bash
.venv/bin/python -m pytest -q --stress src/tests/test_tui_v2_large_vault_validation.py
```

## Notes

- Stress tests are opt-in in this repository (require `--stress`).
- Thresholds are intentionally conservative to reduce environment flakiness while still catching regressions.
