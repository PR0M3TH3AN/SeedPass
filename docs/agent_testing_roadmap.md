# Agent Testing Roadmap

This roadmap tracks how AI-agent driven testing should evolve for SeedPass.

## Current Baseline (Implemented)

The current baseline is available via:

- `python scripts/ai_tui_agent_test.py`
- `docs/ai_agent_tui_testing.md`

Current strengths:

- deterministic end-to-end TUI flow in isolated `HOME`
- structured artifacts (`report.json`, clean/raw transcripts)
- coverage of onboarding, invalid inputs, add/retrieve/search/list/modify/archive, 2FA display, settings toggles, lock/unlock, stats, graceful exit

Known limitations:

- single large scenario can be harder to triage than smaller suites
- prompt matching is text-driven and sensitive to wording changes
- no dedicated “stress mode” for repeated random-but-seeded menu fuzzing yet

## Near-Term Roadmap (Next 1-2 cycles)

1. Split harness into scenario profiles:
   - `core`: fast smoke path
   - `extended`: all entry types + settings paths
   - `stress`: repeated deterministic negative-input cycles
2. Add stricter artifact schema checks:
   - fail when unknown coverage keys appear
   - include app version, git SHA, and runtime metadata in `report.json`
3. Add targeted assertions for critical post-conditions:
   - archive state consistency after restore
   - lock/unlock recovers all managers and key hierarchy
4. Add a compact summary command for agents:
   - parse latest report and print one-line status + failed checkpoints

## Mid-Term Roadmap

1. Differential transcript checks:
   - compare current clean transcript against approved baselines
   - allow configurable “soft differences” (timestamps, progress bars)
2. Seeded input-fuzz campaigns:
   - deterministic generation of invalid menu/index/text inputs
   - reproducible runs via fixed RNG seed in report metadata
3. Failure clustering:
   - classify failures into prompt drift, logic errors, state corruption, crash
4. CI lane for agent harness:
   - run `core` on every PR
   - run `extended` on merge queue/nightly

## Long-Term Roadmap

1. Coverage-driven TUI planning:
   - map harness steps to code regions and prioritize unexercised paths
2. Stateful model checking for menu transitions:
   - verify reachable/valid transitions and back-navigation invariants
3. Multi-profile and migration scenario pack:
   - legacy index import/migration and cross-profile operations in one harness family
4. Security-oriented interactive tests:
   - secret-mode leakage checks in output streams
   - clipboard behavior assertions in controlled environments

## Operating Rules for Agents

1. Prefer deterministic inputs and stable prompt matching.
2. Keep each new checkpoint tied to a concrete user-visible behavior.
3. Add regression tests in `src/tests/` for every discovered logic bug.
4. Treat harness failures as either:
   - product defect to fix, or
   - harness synchronization defect to harden.
5. Record the final decision in PR notes with report paths.
