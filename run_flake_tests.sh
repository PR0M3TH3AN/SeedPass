#!/bin/bash
set -e
mkdir -p artifacts
echo "# Flaky Tests Report" > artifacts/ci-flakes-$(date +%Y%M%d).md

flake_found=0

for i in {1..3}; do
  echo "Running test loop $i..."
  if ! PYTHONPATH=src python3 -m pytest src/tests/ > test_loop_$i.log 2>&1; then
    echo "Test failed on loop $i! See test_loop_$i.log"
    echo "## Loop $i Failure" >> artifacts/ci-flakes-$(date +%Y%M%d).md
    echo "\`\`\`" >> artifacts/ci-flakes-$(date +%Y%M%d).md
    cat test_loop_$i.log >> artifacts/ci-flakes-$(date +%Y%M%d).md
    echo "\`\`\`" >> artifacts/ci-flakes-$(date +%Y%M%d).md
    flake_found=1
  else
    echo "Loop $i passed."
  fi
done

if [ $flake_found -eq 0 ]; then
  echo "No flaky tests detected in 3 loops." >> artifacts/ci-flakes-$(date +%Y%M%d).md
fi
