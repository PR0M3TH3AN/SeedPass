# AI Agent TUI Testing

This document defines a repeatable, methodical TUI test workflow for AI agents.

## Goal

Run SeedPass as a real interactive user and produce deterministic artifacts:

1. Step-level pass/fail.
2. Coverage checkpoints for major TUI features.
3. Full transcript for debugging and regression comparison.

## Runner

Use:

```bash
source .venv/bin/activate
python scripts/ai_tui_agent_test.py
```

The runner:

- creates an isolated temporary `HOME`
- launches `src/main.py --no-clipboard`
- executes an end-to-end scenario through onboarding and major menu flows
- writes artifacts to `artifacts/agent_tui_test/<timestamp>/`

## Agent Commands Today

Use these command tiers when agents are validating changes:

1. Fast targeted checks (recommended during iteration):

```bash
source .venv/bin/activate
pytest -q src/tests/test_manager_add_password.py src/tests/test_archive_restore.py src/tests/test_stats_screen.py src/tests/test_bip85_init.py
python scripts/ai_tui_agent_test.py
```

2. Full regression check (before merge):

```bash
source .venv/bin/activate
pytest -q
python scripts/ai_tui_agent_test.py
```

3. Stability sweep for TUI prompt timing:

```bash
source .venv/bin/activate
python scripts/ai_tui_agent_test.py && python scripts/ai_tui_agent_test.py && python scripts/ai_tui_agent_test.py
```

## Artifacts

Each run writes:

- `report.json`: status, step results, coverage points, failure info.
- `transcript.clean.txt`: ANSI-stripped terminal output.
- `transcript.raw.txt`: raw terminal output with ANSI.

## Current Coverage Points

The harness marks these checkpoints as `true` only when observed:

- `startup_onboarding`
- `main_menu`
- `invalid_input_resilience`
- `add_password_quick`
- `invalid_length_validation`
- `add_totp`
- `add_all_entry_types`
- `retrieve_entry`
- `search_entries`
- `list_entries`
- `modify_entry`
- `archive_restore`
- `totp_codes_view`
- `settings_toggles_lock_unlock`
- `settings_stats`
- `graceful_exit`

## CI/Agent Use Pattern

Recommended agent sequence:

1. `python scripts/ai_tui_agent_test.py`
2. Parse `report.json`
3. Fail task if `status != "passed"` or any checkpoint is `false`
4. If failed, inspect `transcript.clean.txt` for prompt-flow drift or regressions

## Optional Flags

```bash
python scripts/ai_tui_agent_test.py --help
```

Useful options:

- `--timeout`: per-prompt timeout
- `--password`: fixed password used during test
- `--output-dir`: custom artifact root
- `--keep-home`: preserve generated profile state for local debugging
- `--verbose`: print step progress

## Extending Coverage

When adding new TUI flows:

1. Add deterministic steps to `scripts/ai_tui_agent_test.py`.
2. Add a new coverage checkpoint key.
3. Assert on concrete prompt/output text, not timing.
4. Keep inputs deterministic and avoid clipboard-dependent behavior.

## Roadmap

Future testing milestones are tracked in `docs/agent_testing_roadmap.md`.
