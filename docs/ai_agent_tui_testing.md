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
- executes a scenario profile (`core`, `extended`, or `stress`)
- writes artifacts to `artifacts/agent_tui_test/<timestamp>/`

## Scenario Profiles

- `core`: fast smoke path (onboarding, invalid input checks, add/retrieve/search/list, exit)
- `extended`: full end-to-end path including all entry kinds, archive/restore, and settings flows
- `stress`: deterministic repeated negative-input and back-navigation loops

## Agent Commands Today

Use these command tiers when agents are validating changes:

1. Fast targeted checks (recommended during iteration):

```bash
source .venv/bin/activate
pytest -q src/tests/test_manager_add_password.py src/tests/test_archive_restore.py src/tests/test_stats_screen.py src/tests/test_bip85_init.py
pytest -q src/tests/test_ai_tui_agent_harness.py
python scripts/ai_tui_agent_test.py --scenario core
```

2. Full regression check (before merge):

```bash
source .venv/bin/activate
pytest -q
pytest -q --cov=src --cov-report=json:artifacts/coverage/coverage.json src/tests
python scripts/check_critical_coverage.py artifacts/coverage/coverage.json
python scripts/ai_tui_agent_test.py --scenario extended
```

3. Stability sweep for TUI prompt timing:

```bash
source .venv/bin/activate
python scripts/ai_tui_agent_test.py --scenario stress --stress-cycles 6 --stress-seed 1337
```

## Artifacts

Each run writes:

- `report.json`: status, step results, coverage points, failure info.
- `transcript.clean.txt`: ANSI-stripped terminal output.
- `transcript.raw.txt`: raw terminal output with ANSI.

`report.json` also includes scenario-specific validation metadata:

- `required_coverage_keys`
- `required_post_conditions`
- `post_conditions`

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

`extended` scenario also enforces post-conditions:

- `archive_restore_consistency`: restored entries are no longer listed in archived view
- `lock_unlock_recovers_retrieval`: retrieval still works after lock/unlock

## CI/Agent Use Pattern

Recommended agent sequence:

1. `python scripts/ai_tui_agent_test.py`
2. Parse `report.json`
3. Fail task if `status != "passed"` or any checkpoint is `false`
4. If failed, inspect `transcript.clean.txt` for prompt-flow drift or regressions
5. Inspect `artifacts/coverage/coverage.json` and critical coverage gate output when module thresholds fail

## Optional Flags

```bash
python scripts/ai_tui_agent_test.py --help
```

Useful options:

- `--scenario`: `core`, `extended`, or `stress`
- `--stress-cycles`: number of loops for `stress` profile
- `--stress-seed`: fixed RNG seed for deterministic invalid-input campaigns in `stress`
- `--timeout`: per-prompt timeout
- `--password`: fixed password used during test
- `--output-dir`: custom artifact root
- `--keep-home`: preserve generated profile state for local debugging
- `--verbose`: print step progress

Coverage gate helper:

- `python scripts/check_critical_coverage.py artifacts/coverage/coverage.json`
- Use `--threshold PATH=PERCENT` to override defaults.
- Use `--no-default-thresholds` for focused local smoke checks.

## Extending Coverage

When adding new TUI flows:

1. Add deterministic steps to `scripts/ai_tui_agent_test.py`.
2. Add a new coverage checkpoint key.
3. Assert on concrete prompt/output text, not timing.
4. Keep inputs deterministic and avoid clipboard-dependent behavior.

## Roadmap

Future testing milestones are tracked in `docs/agent_testing_roadmap.md`.
