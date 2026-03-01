# Agent Test Format

This document defines the repeatable "agent-style" validation format for
SeedPass TUI v2, CLI/CUI, and API surfaces.

## Goals

- Reproduce user and agent workflows deterministically.
- Generate machine-readable artifacts for regressions.
- Keep a stable command format for local runs and CI runs.

## Output Contract

Each harness run should emit:

- `status`: `passed` or `failed`
- `failure`: short error detail when failed
- `duration_sec`: run duration
- `steps`: per-step status/timing
- `coverage_points`: workflow checkpoints as booleans
- optional transcripts/activity logs

Reports are written to timestamped artifact folders under `artifacts/`.

## TUI v2 Harness

Script:

```bash
python3 scripts/ai_tui2_agent_test.py --scenario extended --verbose
```

Artifacts:

- `artifacts/agent_tui2_test/<timestamp>/report.json`

Scenarios:

- `core`: startup/search/document edit/graph open/archive-restore
- `extended`: `core` + palette unknown command + help overlay/navigation checks

## Legacy Interactive Harness

Script:

```bash
python3 scripts/ai_tui_agent_test.py --scenario extended --python-bin .venv/bin/python --verbose
```

Artifacts:

- `artifacts/agent_tui_test/<timestamp>/report.json`
- transcript files (`transcript.clean.txt`, `transcript.raw.txt`)

Use this for legacy interactive flow regression checks.

## CLI/CUI Agent-Style Validation

Primary command suites:

```bash
pytest -q src/tests/test_cli*.py src/tests/test_typer_cli.py src/tests/test_cli_agent_mode.py
```

This covers user CLI commands and agent command flows.

## API Agent-Style Validation

Primary command suites:

```bash
pytest -q src/tests/test_api*.py
```

This covers auth, policy enforcement, entry/document operations, and vault
endpoints from an API client perspective.

## TUI v2 Deep Coverage Command

To track TUI v2 function/path coverage:

```bash
pytest -q \
  src/tests/test_tui_v2_helpers.py \
  src/tests/test_tui_v2_textual_interactions.py \
  src/tests/test_tui_v2_parity_scenarios.py \
  src/tests/test_tui_v2_large_vault_validation.py \
  src/tests/test_tui_v2_action_matrix.py \
  --cov=seedpass.tui_v2.app \
  --cov-report=term-missing
```

## Determinism Gate Integration

Run deterministic suite:

```bash
./scripts/run_determinism_tests.sh
```

This includes `scripts/check_determinism_suite.py` to enforce suite shape and
minimum determinism test count before executing tests.
