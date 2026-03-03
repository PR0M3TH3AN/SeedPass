#!/usr/bin/env bash
set -euo pipefail

# CI smoke gate for TUI v2 runtime diagnostics.
# Prefer the real CLI command when available; fall back to Typer CliRunner.

export PYTHONPATH=src

if command -v seedpass >/dev/null 2>&1; then
    raw_output="$(seedpass tui2 --check)"
else
    # If poetry is available and not in venv, use poetry run
    # but only if poetry env actually has packages installed (pyproject.toml exists)
    if [[ -z "${VIRTUAL_ENV:-}" ]] && command -v poetry >/dev/null 2>&1 && poetry env info --path >/dev/null 2>&1; then
        cmd_prefix="poetry run "
        py_bin="python"
    else
        cmd_prefix=""
        if [[ -x ".venv/bin/python" ]]; then
            py_bin=".venv/bin/python"
        elif [[ -n "${pythonLocation:-}" && -x "$pythonLocation/python" ]]; then
            py_bin="$pythonLocation/python"
        elif command -v python >/dev/null 2>&1; then
            py_bin="python"
        else
            py_bin="python3"
        fi
    fi

    raw_output="$(${cmd_prefix}${py_bin} - <<'PY'
import json
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

if [[ -z "${VIRTUAL_ENV:-}" ]] && command -v poetry >/dev/null 2>&1 && poetry env info --path >/dev/null 2>&1; then
    cmd_prefix="poetry run "
    py_bin="python"
else
    cmd_prefix=""
    if [[ -x ".venv/bin/python" ]]; then
        py_bin=".venv/bin/python"
    elif [[ -n "${pythonLocation:-}" && -x "$pythonLocation/python" ]]; then
        py_bin="$pythonLocation/python"
    elif command -v python >/dev/null 2>&1; then
        py_bin="python"
    else
        py_bin="python3"
    fi
fi

${cmd_prefix}${py_bin} - <<'PY' "$raw_output"
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
