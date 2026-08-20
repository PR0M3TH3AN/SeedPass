#!/usr/bin/env bash
# The gate that runs before a branch is called ready. Minutes, not seconds.
#
# ci_prepush.sh answers "is this push going to embarrass me". This answers
# "do the two implementations still agree, and does the thing we ship still
# work" -- which is the question SeedPass actually cares about, because the
# TypeScript port only has value if it derives byte-identical secrets to the
# Python it replaces.
#
# Everything expensive lives here on purpose. The cli suite spawns real
# daemons and real subprocesses; the fuzzer runs both implementations over
# generated cases; the packaging check installs the tarball the way a user
# would. None of that belongs on the path of every `git push`.
#
# Fixed seeds, deliberately. GitHub additionally runs an exploratory seed
# derived from the run id so the explored space grows over time; locally you
# want the same cases every run, so a failure is reproducible rather than a
# rumour.
set -euo pipefail
cd "$(dirname "$0")/.."

step() { printf "\n\033[1m==> %s\033[0m\n" "$1"; }

step "everything in ci:prepush"
./scripts/ci_prepush.sh

step "javascript: full test suite (cli included, node + jsdom)"
pnpm -C js test

step "javascript: build and smoke the shipped bundle"
pnpm -C js build
node js/scripts/smoke-cli.mjs

step "python: full test suite"
poetry run pytest -q

step "parity: python <-> typescript cross-implementation"
poetry run python scripts/cross_impl_check.py

step "parity: fixtures still come from the committed generator"
poetry run python scripts/generate_ts_port_fixtures.py
git diff --exit-code -- \
  js/packages/test-vectors/fixtures \
  ':(exclude)js/packages/test-vectors/fixtures/manifest.json'

step "parity: differential fuzz, fixed seeds"
for seed in 1 2 3; do
  poetry run python scripts/differential_fuzz.py --cases 150 --seed "$seed"
done

printf "\n\033[32mci:parity passed.\033[0m This branch is ready for review.\n"
