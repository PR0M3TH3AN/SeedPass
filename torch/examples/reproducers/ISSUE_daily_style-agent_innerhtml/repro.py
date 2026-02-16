import sys
import os

target_file = "torch/landing/index.html"
print(f"Checking {target_file} for innerHTML usage...")

if not os.path.exists(target_file):
    print(f"Error: {target_file} not found.")
    sys.exit(1)

with open(target_file, "r") as f:
    content = f.read()

if "innerHTML" in content:
    print("FAILURE: innerHTML found in file.")
    # Print lines with innerHTML
    lines = content.splitlines()
    for i, line in enumerate(lines):
        if "innerHTML" in line:
            print(f"Line {i+1}: {line.strip()}")
    sys.exit(1)
else:
    print("SUCCESS: No innerHTML found.")
    sys.exit(0)
