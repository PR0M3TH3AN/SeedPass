#!/usr/bin/env bash
set -eo pipefail

pytest_args=(-vv --desktop -m desktop src/tests)
if [[ "${RUNNER_OS:-}" == "Windows" ]]; then
    pytest_args+=(-n 1)
fi

timeout_bin="timeout"
if ! command -v "$timeout_bin" >/dev/null 2>&1; then
    if command -v gtimeout >/dev/null 2>&1; then
        timeout_bin="gtimeout"
    else
        timeout_bin=""
    fi
fi

if [[ -n "$timeout_bin" ]]; then
    $timeout_bin 10m pytest "${pytest_args[@]}" 2>&1 | tee pytest_gui.log
    status=${PIPESTATUS[0]}
else
    echo "timeout command not found; running tests without timeout" >&2
    pytest "${pytest_args[@]}" 2>&1 | tee pytest_gui.log
    status=${PIPESTATUS[0]}
fi

if [[ $status -eq 124 ]]; then
    echo "::error::Desktop tests exceeded 10-minute limit"
    tail -n 20 pytest_gui.log
    exit 1
fi
exit $status
