"""Utilities for release checksum generation and verification."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Iterable


def _file_sha256(file_path: Path) -> str:
    hasher = hashlib.sha256()
    with file_path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def collect_artifacts(paths: Iterable[Path]) -> list[Path]:
    """Return deterministic, deduplicated file list for checksum operations."""
    collected: list[Path] = []
    for path in paths:
        candidate = path.expanduser().resolve()
        if not candidate.exists():
            raise FileNotFoundError(f"Artifact path does not exist: {path}")
        if candidate.is_file():
            collected.append(candidate)
            continue
        if candidate.is_dir():
            for artifact in sorted(p for p in candidate.rglob("*") if p.is_file()):
                collected.append(artifact.resolve())

    unique: dict[str, Path] = {}
    for artifact in sorted(collected, key=lambda p: str(p)):
        unique[str(artifact)] = artifact
    return list(unique.values())


def generate_checksums(
    artifacts: Iterable[Path], base_dir: Path | None = None
) -> list[str]:
    """Generate SHA256SUMS-compatible lines for provided artifacts."""
    resolved_artifacts = collect_artifacts(artifacts)
    root = base_dir.resolve() if base_dir else None
    lines: list[str] = []
    for artifact in resolved_artifacts:
        digest = _file_sha256(artifact)
        display_path = (
            artifact.relative_to(root).as_posix()
            if root and artifact.is_relative_to(root)
            else artifact.name
        )
        lines.append(f"{digest}  {display_path}")
    return lines


def parse_checksum_line(line: str) -> tuple[str, str]:
    """Parse a SHA256SUMS line into digest and path."""
    cleaned = line.strip()
    if not cleaned:
        raise ValueError("Checksum line cannot be empty")
    if "  " not in cleaned:
        raise ValueError(f"Checksum line is malformed: {line!r}")
    digest, path = cleaned.split("  ", 1)
    digest = digest.strip()
    path = path.strip()
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise ValueError(f"Invalid SHA-256 digest: {digest!r}")
    if not path:
        raise ValueError("Checksum path cannot be empty")
    return digest, path


def verify_checksums(
    checksum_file: Path, base_dir: Path | None = None
) -> tuple[bool, list[str]]:
    """Verify checksums listed in checksum_file against files in base_dir/current dir."""
    root = base_dir.resolve() if base_dir else Path.cwd().resolve()
    failures: list[str] = []
    for idx, line in enumerate(
        checksum_file.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip():
            continue
        try:
            expected, rel_path = parse_checksum_line(line)
        except ValueError as exc:
            failures.append(f"Line {idx}: {exc}")
            continue
        target = (root / rel_path).resolve()
        if not target.exists():
            failures.append(f"Line {idx}: missing file {rel_path}")
            continue
        actual = _file_sha256(target)
        if actual != expected:
            failures.append(f"Line {idx}: checksum mismatch for {rel_path}")
    return (len(failures) == 0, failures)
