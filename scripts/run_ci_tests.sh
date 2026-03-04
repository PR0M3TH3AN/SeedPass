#!/usr/bin/env bash
set -eo pipefail

mkdir -p artifacts/coverage

if [[ "${TUI2_SMOKE_GATE:-0}" == "1" ]]; then
    ./scripts/tui2_check_smoke.sh
fi

if [[ -x ".venv/bin/python" ]]; then
    py_bin=".venv/bin/python"
elif command -v python >/dev/null 2>&1; then
    py_bin="python"
else
    py_bin="python3"
fi

if [[ "${DETERMINISM_GATE:-1}" == "1" ]]; then
    ./scripts/run_determinism_tests.sh
fi

pytest_args=(-vv)
if [[ -n "${STRESS_ARGS:-}" ]]; then
    pytest_args+=(${STRESS_ARGS})
fi
if [[ "${RUNNER_OS:-}" == "Windows" ]]; then
    pytest_args+=(-n 1)
fi
pytest_args+=(
    --cov=src
    --cov-report=xml
    --cov-report=term-missing
    --cov-report=json:artifacts/coverage/coverage.json
    --cov-fail-under=20
    src/tests
)

timeout_bin="timeout"
if ! command -v "$timeout_bin" >/dev/null 2>&1; then
    if command -v gtimeout >/dev/null 2>&1; then
        timeout_bin="gtimeout"
    else
        timeout_bin=""
    fi
fi

if [[ -n "$timeout_bin" ]]; then
    $timeout_bin 15m "$py_bin" -m pytest "${pytest_args[@]}" 2>&1 | tee pytest.log
    status=${PIPESTATUS[0]}
else
    echo "timeout command not found; running tests without timeout" >&2
    "$py_bin" -m pytest "${pytest_args[@]}" 2>&1 | tee pytest.log
    status=${PIPESTATUS[0]}
fi

if [[ $status -eq 124 ]]; then
    echo "::error::Tests exceeded 15-minute limit"
    tail -n 20 pytest.log
    exit 1
fi
if [[ $status -eq 0 && "${CRITICAL_COVERAGE_GATE:-1}" == "1" ]]; then
    "$py_bin" scripts/check_critical_coverage.py \
        artifacts/coverage/coverage.json \
        --json-output artifacts/coverage/critical_gate.full.json
fi
if [[ $status -eq 0 && "${TUI2_COVERAGE_GATE:-0}" == "1" ]]; then
    ./scripts/tui2_coverage_gate.sh
fi
if [[ $status -eq 0 && "${TUI3_COVERAGE_GATE:-1}" == "1" ]]; then
    ./scripts/tui3_coverage_gate.sh
fi
exit $status
