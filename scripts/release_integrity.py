#!/usr/bin/env python3
"""Release integrity checks and checksum manifest tooling."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from seedpass.release_integrity import generate_checksums, verify_checksums


def _check_lockfile(lockfile: Path) -> tuple[bool, list[str]]:
    issues: list[str] = []
    if not lockfile.exists():
        return False, [f"Missing lockfile: {lockfile}"]

    package_line_count = 0
    hash_count = 0
    for raw_line in lockfile.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("--hash=sha256:"):
            hash_count += 1
            continue
        if "==" in line and not line.startswith(("-", "\\")):
            package_line_count += 1

    if package_line_count == 0:
        issues.append("No pinned package entries found in lockfile.")
    if hash_count == 0:
        issues.append("No sha256 hashes found in lockfile.")
    return len(issues) == 0, issues


def cmd_generate(args: argparse.Namespace) -> int:
    artifacts = [Path(path) for path in args.artifact]
    lines = generate_checksums(artifacts, base_dir=Path(args.base_dir))
    output_file = Path(args.output)
    output_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {len(lines)} checksums to {output_file}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    checksum_file = Path(args.checksum_file)
    ok, failures = verify_checksums(checksum_file, base_dir=Path(args.base_dir))
    if ok:
        print(f"Checksum verification passed: {checksum_file}")
        return 0
    print(f"Checksum verification failed for {checksum_file}:")
    for failure in failures:
        print(f" - {failure}")
    return 1


def cmd_check_lockfile(args: argparse.Namespace) -> int:
    lockfile = Path(args.lockfile)
    ok, issues = _check_lockfile(lockfile)
    if ok:
        print(f"Lockfile integrity checks passed: {lockfile}")
        return 0
    print(f"Lockfile integrity checks failed for {lockfile}:")
    for issue in issues:
        print(f" - {issue}")
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate_parser = subparsers.add_parser(
        "generate", help="Generate SHA256SUMS manifest"
    )
    generate_parser.add_argument(
        "--artifact",
        action="append",
        required=True,
        help="Artifact file or directory. Pass multiple times for multiple paths.",
    )
    generate_parser.add_argument(
        "--output", default="SHA256SUMS", help="Checksum output file"
    )
    generate_parser.add_argument(
        "--base-dir",
        default=".",
        help="Base directory used to render relative paths in SHA256SUMS.",
    )
    generate_parser.set_defaults(func=cmd_generate)

    verify_parser = subparsers.add_parser("verify", help="Verify SHA256SUMS manifest")
    verify_parser.add_argument("--checksum-file", default="SHA256SUMS")
    verify_parser.add_argument(
        "--base-dir",
        default=".",
        help="Base directory used to resolve file paths from SHA256SUMS.",
    )
    verify_parser.set_defaults(func=cmd_verify)

    lockfile_parser = subparsers.add_parser(
        "check-lockfile", help="Validate lockfile has pinned packages and hashes"
    )
    lockfile_parser.add_argument("--lockfile", default="requirements.lock")
    lockfile_parser.set_defaults(func=cmd_check_lockfile)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
