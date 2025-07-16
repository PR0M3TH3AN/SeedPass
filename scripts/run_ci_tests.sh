#!/usr/bin/env bash
set -eo pipefail
timeout 15m pytest -vv ${STRESS_ARGS} \
    --cov=src --cov-report=xml --cov-report=term-missing \
    --cov-fail-under=20 src/tests 2>&1 | tee pytest.log
status=${PIPESTATUS[0]}
if [[ $status -eq 124 ]]; then
    echo "::error::Tests exceeded 15-minute limit"
    tail -n 20 pytest.log
    exit 1
fi
exit $status
