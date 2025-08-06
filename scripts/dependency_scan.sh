#!/usr/bin/env bash
set -euo pipefail

# Run pip-audit against the installed environment
if ! command -v pip-audit >/dev/null 2>&1; then
  python -m pip install --quiet pip-audit
fi

pip-audit "$@"
