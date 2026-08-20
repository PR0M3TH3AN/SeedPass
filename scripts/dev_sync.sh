#!/usr/bin/env bash
# Bring this machine's toolchains into agreement with the lockfiles.
#
# The counterpart to scripts/ci_preflight.py, which only ever CHECKS. The
# split is deliberate: a gate that silently repairs your environment hides the
# drift it exists to surface, and you find out on GitHub instead.
#
# This one mutates. `poetry sync` will DOWNGRADE packages that are ahead of
# poetry.lock -- that is the point, since the lockfile is what CI installs.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> poetry sync (installs exactly poetry.lock, removing anything else)"
poetry sync

echo "==> corepack enable (pins pnpm to package.json's packageManager)"
corepack enable

echo "==> pnpm install --frozen-lockfile"
pnpm -C js install --frozen-lockfile

echo
echo "Re-checking:"
exec python3 scripts/ci_preflight.py
