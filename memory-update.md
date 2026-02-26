### 1. [2026-02-26] (github-actions, ci, workflow)
When using `actions/setup-python` with `cache: poetry`, Poetry must already be available on PATH during that step. In SeedPass `tests.yml`, this caused failures because Poetry was installed later via `pipx`; switching to `cache: pip` resolved the immediate bootstrap error.
