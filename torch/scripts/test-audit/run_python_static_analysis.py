import json
import os
import re
from pathlib import Path

# Configuration
TEST_DIR = Path("src/tests")
OUTPUT_DIR = Path("reports/test-audit")
SUSPICIOUS = []

# Patterns to look for
PATTERNS = [
    (r"time\.sleep\(", "Found time.sleep()"),
    (r"@pytest\.mark\.skip", "Found @pytest.mark.skip"),
    (r"@unittest\.skip", "Found @unittest.skip"),
    # Naive weak assertion checks
    (r"assert True", "Found assert True"),
    # Checking for specific flakiness-hiding comments
    (r"# flaky", "Found '# flaky' comment"),
    (r"# todo", "Found '# todo' comment"),
]

def scan_file(filepath):
    """Scan a single file for suspicious patterns."""
    issues = []
    try:
        content = filepath.read_text(encoding="utf-8")
    except Exception:
        return # Skip non-text files

    for pattern, message in PATTERNS:
        if re.search(pattern, content):
            issues.append(message)

    # Check for lack of assertions (very naive)
    if "test_" in filepath.name and "assert" not in content and "expect" not in content and "raise" not in content:
        # Exclude conftest or helpers
        if "conftest" not in filepath.name and "helper" not in filepath.name:
             issues.append("No obvious assertions found")

    if issues:
        SUSPICIOUS.append({
            "file": str(filepath),
            "issues": issues
        })

def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    if not TEST_DIR.exists():
        print(f"Test directory {TEST_DIR} not found.")
        return

    for root, dirs, files in os.walk(TEST_DIR):
        for file in files:
            if file.endswith(".py"):
                scan_file(Path(root) / file)

    with open(OUTPUT_DIR / "suspicious-tests.json", "w") as f:
        json.dump(SUSPICIOUS, f, indent=2)

    print(f"Found {len(SUSPICIOUS)} suspicious files.")
    print(f"Report written to {OUTPUT_DIR / 'suspicious-tests.json'}.")

if __name__ == "__main__":
    main()
