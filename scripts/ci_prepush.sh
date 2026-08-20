#!/usr/bin/env bash
# The gate that runs before every push. Target: well under a minute.
#
# WHAT IS IN HERE AND WHY THAT LIST
#
# The budget is the design constraint, not an afterthought. A hook that takes
# minutes becomes `git push --no-verify` within a week, at which point it is a
# ceremonial control that everyone believes in and nobody runs. So this holds
# only checks that are cheap AND catch things CI would otherwise catch late.
#
# Measured on this machine, 2026-08-20:
#
#     preflight                    2.6s
#     poetry check --lock          0.6s
#     black --check                2.5s
#     oxlint                       0.9s
#     tsc --noEmit (workspace)     7.3s
#     pytest determinism subset    5.4s
#     vitest core (node)          24.0s
#                                 -----
#                                 ~44s
#
# What is deliberately NOT here:
#
#     vitest cli                 176.3s   <- alone, three times the budget
#     pytest (full)              ~350s
#     cross-impl, fuzz, packaging smoke
#
# Those live in ci_parity.sh, which is what you run before calling a branch
# ready rather than before every push. The cli suite is slow for a good
# reason -- it spawns real daemons, real sockets and real subprocesses rather
# than mocking them -- and that is worth keeping, not worth waiting on twenty
# times a day.
#
# EVERY TOOL IS INVOKED THROUGH THE REPOSITORY ENVIRONMENT. `poetry run ...`
# and `pnpm -C js ...`, never a bare `black` or `vitest` off PATH. That rule is
# the whole reason preflight runs first: a bare tool name is how a local gate
# ends up passing while CI fails.
set -euo pipefail
cd "$(dirname "$0")/.."

step() { printf "\n\033[1m==> %s\033[0m\n" "$1"; }

step "preflight: does this machine agree with the lockfiles?"
python3 scripts/ci_preflight.py

step "python: lockfile consistency"
poetry check --lock

step "python: formatting (the pinned black, not whatever is on PATH)"
poetry run black --check .

step "javascript: lint"
pnpm -C js lint

step "javascript: typecheck"
pnpm -C js typecheck

step "javascript: core tests"
pnpm -C js --filter @seedpass/core test:node

step "python: deterministic artifact regression"
poetry run pytest -q src/tests/test_deterministic_artifact_regression.py

if command -v actionlint >/dev/null 2>&1; then
  step "workflows: actionlint"
  actionlint
else
  printf "\n\033[2m(actionlint not installed — skipping workflow lint)\033[0m\n"
fi

printf "\n\033[32mci:prepush passed.\033[0m Run ./scripts/ci_parity.sh before calling a branch ready.\n"
