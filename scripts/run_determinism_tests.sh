#!/usr/bin/env bash
set -eo pipefail

timeout_bin="timeout"
if ! command -v "$timeout_bin" >/dev/null 2>&1; then
    if command -v gtimeout >/dev/null 2>&1; then
        timeout_bin="gtimeout"
    else
        timeout_bin=""
    fi
fi

pytest_args=(
    -q
    --maxfail=1
    --determinism-only
    src/tests
)

pytest_bin="pytest"
if ! command -v "$pytest_bin" >/dev/null 2>&1; then
    if [[ -x ".venv/bin/pytest" ]]; then
        pytest_bin=".venv/bin/pytest"
    else
        echo "pytest not found on PATH and .venv/bin/pytest is missing" >&2
        exit 2
    fi
fi

if [[ -n "$timeout_bin" ]]; then
    $timeout_bin 2m python3 scripts/check_determinism_suite.py \
        --pytest-bin "$pytest_bin" \
        --min-tests "${DETERMINISM_MIN_TESTS:-25}"
    $timeout_bin 10m "$pytest_bin" "${pytest_args[@]}"
else
    echo "timeout command not found; running determinism tests without timeout" >&2
    python3 scripts/check_determinism_suite.py \
        --pytest-bin "$pytest_bin" \
        --min-tests "${DETERMINISM_MIN_TESTS:-25}"
    "$pytest_bin" "${pytest_args[@]}"
fi
