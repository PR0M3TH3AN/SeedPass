#!/usr/bin/env python3
"""
Utility script to export a SeedPass profile (JSON format) to a CSV file.
This can be useful for migrating data to other password managers or analyzing passwords.

Usage:
  python features/export-json-to-csv.py <path_to_profile.json> <output_file.csv>

Example:
  python features/export-json-to-csv.py ~/.seedpass/profiles/demo_profile.json passwords.csv
"""

import sys
import json
import csv
import os


def export_json_to_csv(input_path, output_path):
    if not os.path.exists(input_path):
        print(f"Error: Input file '{input_path}' not found.")
        sys.exit(1)

    try:
        with open(input_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError:
        print(f"Error: Could not parse JSON from '{input_path}'.")
        sys.exit(1)

    # Note: SeedPass profiles are usually encrypted and managed by the app,
    # but this utility can operate on exported or decrypted JSON index files.
    if not isinstance(data, list):
        print("Error: Expected a JSON array of entries.")
        sys.exit(1)

    if not data:
        print("Warning: Input JSON is empty. Creating an empty CSV.")
        fieldnames = []
    else:
        # Collect all possible field names
        fieldnames = set()
        for entry in data:
            if isinstance(entry, dict):
                fieldnames.update(entry.keys())
        fieldnames = sorted(list(fieldnames))

    try:
        with open(output_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for entry in data:
                if isinstance(entry, dict):
                    writer.writerow(entry)
        print(f"Success: Exported {len(data)} entries to '{output_path}'.")
    except Exception as e:
        print(f"Error writing to CSV: {e}")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    export_json_to_csv(input_file, output_file)
