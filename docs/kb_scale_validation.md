# KB Scale Validation

Status: Added on `beta` (March 1, 2026).

This document defines stress-oriented validation for knowledge-base behavior
under large index counts.

## Coverage

1. Sort/tag/search over large indexes:
  - `src/tests/test_kb_scale_stress.py::test_kb_sort_tag_search_scale`
2. High-degree graph link handling:
  - `src/tests/test_kb_scale_stress.py::test_kb_graph_high_degree_links_scale`
3. Textual TUI v2 large-index interactions:
  - `src/tests/test_tui_v2_kb_scale_stress.py::test_tui2_kb_large_index_navigation`

## Dataset Profiles

- Standard:
  - `10,000` entries for sort/search/tag
  - `1,000` graph edges from one source node
  - `10,000` TUI rows
- Stress (`--stress`):
  - `100,000` entries for sort/search/tag
  - `5,000` graph edges from one source node
  - `50,000` TUI rows

## Commands

Standard run:

```bash
.venv/bin/python -m pytest -q src/tests/test_kb_scale_stress.py src/tests/test_tui_v2_kb_scale_stress.py
```

Stress run:

```bash
.venv/bin/python -m pytest -q --stress src/tests/test_kb_scale_stress.py src/tests/test_tui_v2_kb_scale_stress.py
```

## Notes

- Stress scenarios are opt-in and require `--stress`.
- Time budgets are intentionally conservative to catch regressions while
  reducing CI flakiness across environments.
