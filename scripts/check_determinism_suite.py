#!/usr/bin/env python3
"""Validate determinism test-suite shape before running CI-heavy jobs."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

DEFAULT_REQUIRED_FILES = [
    "src/tests/test_cross_process_determinism.py",
    "src/tests/test_deterministic_artifact_regression.py",
    "src/tests/test_document_file_io.py",
    "src/tests/test_full_sync_roundtrip.py",
    "src/tests/test_nostr_snapshot.py",
    "src/tests/test_password_generation_policy.py",
    "src/tests/test_password_helpers.py",
    "src/tests/test_seed_entry.py",
    "src/tests/test_ssh_entry.py",
    "src/tests/test_pgp_entry.py",
    "src/tests/test_nostr_entry.py",
]


def _extract_nodeids(collected_output: str) -> list[str]:
    nodeids: list[str] = []
    for line in collected_output.splitlines():
        raw = line.strip()
        if "::" not in raw:
            continue
        if raw.startswith("<") or raw.startswith("="):
            continue
        nodeids.append(raw)
    return nodeids


def _extract_file_set(nodeids: list[str]) -> set[str]:
    files: set[str] = set()
    for nodeid in nodeids:
        files.add(nodeid.split("::", 1)[0].replace("\\", "/"))
    return files


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Ensure determinism tests remain comprehensive."
    )
    parser.add_argument(
        "--pytest-bin",
        default="pytest",
        help="pytest executable to use (default: pytest).",
    )
    parser.add_argument(
        "--min-tests",
        type=int,
        default=25,
        help="Minimum required collected tests with marker 'determinism'.",
    )
    parser.add_argument(
        "--tests-root",
        default="src/tests",
        help="Root test path for pytest collection (default: src/tests).",
    )
    parser.add_argument(
        "--require-file",
        action="append",
        default=[],
        help="Required file that must contribute at least one determinism test.",
    )
    parser.add_argument(
        "--no-default-required-files",
        action="store_true",
        help="Disable built-in required file checks.",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    pytest_bin = shutil.which(args.pytest_bin) if args.pytest_bin else None
    if pytest_bin is None:
        print(f"Error: pytest binary not found: {args.pytest_bin}", file=sys.stderr)
        return 2

    cmd = [
        pytest_bin,
        "--collect-only",
        "-q",
        "-m",
        "determinism",
        args.tests_root,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        print("Error: failed to collect determinism tests.", file=sys.stderr)
        if result.stdout:
            print(result.stdout, file=sys.stderr)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        return 2

    nodeids = _extract_nodeids(result.stdout)
    files = _extract_file_set(nodeids)
    required_files = (
        [] if args.no_default_required_files else list(DEFAULT_REQUIRED_FILES)
    )
    required_files.extend(args.require_file)
    required_files = [f.replace("\\", "/") for f in required_files]
    missing_files = sorted([f for f in required_files if f not in files])

    print(f"Determinism tests collected: {len(nodeids)}")
    if files:
        print(f"Determinism files present: {len(files)}")

    if len(nodeids) < args.min_tests:
        print(
            f"FAIL: determinism suite below minimum test count ({len(nodeids)} < {args.min_tests})",
            file=sys.stderr,
        )
        return 1

    if missing_files:
        print(
            "FAIL: determinism suite missing required files:\n- "
            + "\n- ".join(missing_files),
            file=sys.stderr,
        )
        return 1

    print("Determinism suite gate passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
