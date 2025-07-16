#!/usr/bin/env bash
set -eo pipefail

pytest_cmd=(pytest -vv ${STRESS_ARGS} \
    --cov=src --cov-report=xml --cov-report=term-missing \
    --cov-fail-under=20 src/tests)

timeout_bin="timeout"
if ! command -v "$timeout_bin" >/dev/null 2>&1; then
    if command -v gtimeout >/dev/null 2>&1; then
        timeout_bin="gtimeout"
    else
        timeout_bin=""
    fi
fi

if [[ -n "$timeout_bin" ]]; then
    $timeout_bin 15m "${pytest_cmd[@]}" 2>&1 | tee pytest.log
    status=${PIPESTATUS[0]}
else
    echo "timeout command not found; running tests without timeout" >&2
    "${pytest_cmd[@]}" 2>&1 | tee pytest.log
    status=${PIPESTATUS[0]}
fi

if [[ $status -eq 124 ]]; then
    echo "::error::Tests exceeded 15-minute limit"
    tail -n 20 pytest.log
    exit 1
fi
exit $status
