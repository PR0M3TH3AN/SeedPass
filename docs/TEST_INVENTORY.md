# Test Infrastructure Inventory

This document provides a central index of all SeedPass tests, runners, and automation scripts.

## Core Test Runners

| Script / Command | Target | Coverage |
|-----------------|--------|----------|
| `bash scripts/run_ci_tests.sh` | **Full Suite** | Pytest (CLI, API, TUI v2), Determinism, Coverage |
| `pytest src/tests/` | **Unit/Integration** | Core logic, API, CLI, Encryption |
| `bash scripts/run_gui_tests.sh` | **GUI (BeeWare)** | Headless & Desktop GUI behavioral tests |
| `bash run_flake_tests.sh` | **Stability** | Runs suite multiple times to catch flakes |
| `.venv/bin/python scripts/interactive_agent_tui_test.py` | **Interactive TUI v2** | Mock-service based exploratory walkthrough |

## Specialized Automation

### Determinism
- `bash scripts/run_determinism_tests.sh`: Validates BIP85 compliance and cross-platform artifact consistency.

### TUI v2 Specific
- `src/tests/test_tui_v2_*`: Textual-based unit tests for the v2 interface.
- `scripts/ai_tui2_agent_test.py`: Legacy agent harness for TUI v2.
- `docs/INTERACTIVE_AGENT_TESTING.md`: Guide for manual/agent exploratory testing.

### API & CLI
- `src/tests/test_api*.py`: FastAPI-based backend endpoints.
- `src/tests/test_typer_cli.py`: Typer-based command line interface.

## Test Data & Artifacts
- `artifacts/coverage/`: Generated HTML/JSON coverage reports.
- `artifacts/ci-flakes-*.md`: Logs from flaky test detection runs.

## Guidelines for Agents
1. **Always run CI tests** before proposing changes: `bash scripts/run_ci_tests.sh`.
2. **Add regression tests** in `src/tests/` for every bug fix.
3. **Use Mock Services** for TUI testing to avoid credential requirements (see `scripts/interactive_agent_tui_test.py`).
