import json
import subprocess
import sys
import time
from pathlib import Path

# Configuration
RUNS = 5
OUTPUT_DIR = Path("reports/test-audit")
TEST_PATTERN = "src/tests"
RESULTS = {}
RUN_DIAGNOSTICS = []

def run_tests(run_index):
    """Run pytest and parse output for pass/fail counts."""
    print(f"Run {run_index + 1}/{RUNS}...")

    # We use pytest with simple output to count results
    # -q: quiet
    # --no-header --no-summary: minimal output
    cmd = [
        sys.executable, "-m", "pytest",
        TEST_PATTERN,
        "-q",
        "--no-header",
        "--no-summary"
    ]

    start_time = time.time()
    try:
        # Capture output. Pytest returns 0 (all pass), 1 (tests failed), 5 (no tests), etc.
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env={"PYTHONPATH": "src"}  # Ensure src is in path
        )
        output = result.stdout
        exit_code = result.returncode
    except Exception as e:
        print(f"Error running pytest: {e}")
        return

    duration = time.time() - start_time

    # Parse output character by character for status
    # . = pass, F = fail, E = error, s = skip, x = xfail, X = xpass
    passed = output.count('.')
    failed = output.count('F')
    errors = output.count('E')
    skipped = output.count('s')

    # Store aggregate results (naive mapping, ideally we'd parse node ids)
    # Since we can't easily map node IDs without -v or --junitxml, we track totals for flakiness *rates* at suite level first.
    # To do per-test tracking, we'd need --junitxml per run.

    junit_path = OUTPUT_DIR / f"flaky-run-{run_index + 1}.xml"
    subprocess.run(
        [sys.executable, "-m", "pytest", TEST_PATTERN, f"--junitxml={junit_path}", "-q"],
        capture_output=True, # We only care about the XML file
        env={"PYTHONPATH": "src"}
    )

    RUN_DIAGNOSTICS.append({
        "run": run_index + 1,
        "code": exit_code,
        "duration": duration,
        "passed": passed,
        "failed": failed,
        "errors": errors,
        "skipped": skipped
    })

def parse_junit_xmls():
    """Parse generated JUnit XML files to detect per-test flakiness."""
    import xml.etree.ElementTree as ET

    test_stats = {} # "test_id": {pass: 0, fail: 0, error: 0, skip: 0}

    for i in range(RUNS):
        xml_path = OUTPUT_DIR / f"flaky-run-{i + 1}.xml"
        if not xml_path.exists():
            continue

        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            for testcase in root.iter("testcase"):
                classname = testcase.get("classname")
                name = testcase.get("name")
                test_id = f"{classname}::{name}"

                if test_id not in test_stats:
                    test_stats[test_id] = {"pass": 0, "fail": 0, "error": 0, "skip": 0}

                # Check status
                if testcase.find("failure") is not None:
                    test_stats[test_id]["fail"] += 1
                elif testcase.find("error") is not None:
                    test_stats[test_id]["error"] += 1
                elif testcase.find("skipped") is not None:
                    test_stats[test_id]["skip"] += 1
                else:
                    test_stats[test_id]["pass"] += 1

        except Exception as e:
            print(f"Failed to parse {xml_path}: {e}")

    return test_stats

def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Install pytest if missing (unlikely in this env given prompt, but safe)
    # Skipping install as per instructions "ensure dependencies are installed" happened earlier.

    for i in range(RUNS):
        run_tests(i)

    # Analyze results
    flakiness_matrix = parse_junit_xmls()

    # Write reports
    with open(OUTPUT_DIR / "flakiness-matrix.json", "w") as f:
        json.dump(flakiness_matrix, f, indent=2)

    with open(OUTPUT_DIR / "flakiness-runs.json", "w") as f:
        json.dump(RUN_DIAGNOSTICS, f, indent=2)

    print(f"Flakiness matrix written to {OUTPUT_DIR / 'flakiness-matrix.json'}")

if __name__ == "__main__":
    main()
