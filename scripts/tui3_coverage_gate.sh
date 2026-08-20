#!/usr/bin/env bash
set -euo pipefail

mkdir -p artifacts/coverage

if [[ -x ".venv/bin/python" ]]; then
    py_bin=".venv/bin/python"
elif command -v python >/dev/null 2>&1; then
    py_bin="python"
else
    py_bin="python3"
fi

if ! "$py_bin" - <<'PY' >/dev/null 2>&1
import importlib.util
raise SystemExit(0 if importlib.util.find_spec("textual") else 1)
PY
then
    if [[ "${REQUIRE_TEXTUAL:-0}" == "1" ]]; then
        echo "Error: textual runtime is unavailable; cannot run TUI v3 coverage gate." >&2
        exit 1
    fi
    echo "tui3 coverage gate: skipped (textual runtime unavailable)"
    exit 0
fi

"$py_bin" -m pytest -q \
    --cov=src \
    --cov-report=json:artifacts/coverage/coverage.tui3_gate.json \
    src/tests/test_tui_v3_parity.py \
    src/tests/test_tui_v3_smoke.py

"$py_bin" scripts/check_critical_coverage.py \
    artifacts/coverage/coverage.tui3_gate.json \
    --no-default-thresholds \
    --threshold src/seedpass/tui_v3/app.py=35 \
    --json-output artifacts/coverage/critical_gate.tui3.json

echo "tui3 coverage gate: ok"
