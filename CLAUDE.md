# SeedPass Agent Guide

## Planning & Strategy
Consult these first to align with current objectives:
- **[Dev Control Center](docs/dev_control_center.md)**: Current priorities.
- **[TUI v2 Execution Plan](docs/tui_v2_integration_execution_plan_2026-03-02.md)**: Roadmap for TUI v2.

## Testing
Always run the full suite before proposing changes:
- `bash scripts/run_ci_tests.sh`
- Central Index: **[Test Infrastructure Inventory](docs/TEST_INVENTORY.md)**

## TORCH Memory Integration
You have access to the TORCH memory system.
1. READ: Check `.scheduler-memory/latest/${cadence}/memories.md` for past learnings.
2. WRITE: Before exiting, save new insights to `memory-update.md` so future runs can learn from this session.
