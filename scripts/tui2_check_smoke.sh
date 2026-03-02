#!/usr/bin/env bash
set -euo pipefail

# CI smoke gate for TUI v2 runtime diagnostics.
# Prefer the real CLI command when available; fall back to Typer CliRunner.

if command -v seedpass >/dev/null 2>&1; then
    raw_output="$(seedpass tui2 --check)"
else
    py_bin="python"
    if ! command -v "$py_bin" >/dev/null 2>&1; then
        py_bin="python3"
    fi
    raw_output="$("$py_bin" - <<'PY'
import json
import sys
import os
sys.path.insert(0, os.path.abspath('src'))
from typer.testing import CliRunner
from seedpass.cli import app

runner = CliRunner()
result = runner.invoke(app, ["tui2", "--check"])
if result.exit_code != 0:
    raise SystemExit(result.exit_code)
print(result.stdout.strip())
PY
)"
fi

py_bin="python"
if ! command -v "$py_bin" >/dev/null 2>&1; then
    py_bin="python3"
fi

"$py_bin" - <<'PY' "$raw_output"
import json
import sys

text = sys.argv[1].strip()
data = json.loads(text)
required = {"status", "backend", "textual_available", "message"}
missing = sorted(required - set(data))
if missing:
    raise SystemExit(f"tui2 --check missing keys: {', '.join(missing)}")
if data.get("backend") != "textual":
    raise SystemExit("tui2 --check backend mismatch")
print("tui2 --check smoke: ok")
PY
