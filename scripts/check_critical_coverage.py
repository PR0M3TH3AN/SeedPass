#!/usr/bin/env python3
"""
Enforce coverage thresholds for critical SeedPass modules.

Reads coverage.py JSON output (pytest --cov-report=json:<path>) and:
1. Fails if critical modules are below configured coverage thresholds.
2. Reports fully uncovered functions/methods for those modules.
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from dataclasses import dataclass
from pathlib import Path

DEFAULT_THRESHOLDS: dict[str, float] = {
    "src/main.py": 50.0,
    "src/seedpass/core/manager.py": 60.0,
    "src/seedpass/core/api.py": 85.0,
    "src/seedpass/core/encryption.py": 80.0,
    "src/seedpass/core/migrations.py": 90.0,
}


@dataclass(frozen=True)
class FunctionCoverage:
    name: str
    start_line: int
    end_line: int
    covered: bool


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate coverage thresholds for critical modules."
    )
    parser.add_argument(
        "coverage_json",
        type=Path,
        help="Path to coverage JSON report.",
    )
    parser.add_argument(
        "--threshold",
        action="append",
        default=[],
        metavar="PATH=PERCENT",
        help="Override/add threshold mapping, e.g. src/main.py=40",
    )
    parser.add_argument(
        "--no-default-thresholds",
        action="store_true",
        help="Disable built-in threshold set; use only --threshold entries.",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Repository root for resolving module paths.",
    )
    parser.add_argument(
        "--json-output",
        type=Path,
        default=None,
        help="Optional path to write machine-readable gate results JSON.",
    )
    return parser.parse_args()


def _parse_threshold_overrides(values: list[str]) -> dict[str, float]:
    parsed: dict[str, float] = {}
    for item in values:
        if "=" not in item:
            raise ValueError(
                f"Invalid --threshold value {item!r}; expected PATH=PERCENT"
            )
        path, raw_percent = item.split("=", 1)
        path = path.strip()
        if not path:
            raise ValueError(f"Invalid --threshold value {item!r}; empty path")
        try:
            percent = float(raw_percent)
        except ValueError as exc:
            raise ValueError(
                f"Invalid --threshold value {item!r}; percent must be numeric"
            ) from exc
        if not (0.0 <= percent <= 100.0):
            raise ValueError(
                f"Invalid --threshold value {item!r}; percent must be 0..100"
            )
        parsed[path] = percent
    return parsed


def _load_coverage_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimeError(f"Coverage JSON not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid coverage JSON: {path}: {exc}") from exc


def _normalize_path(path: str) -> str:
    return path.replace("\\", "/")


def _find_file_payload(files_payload: dict, module_path: str):
    module_norm = _normalize_path(module_path)
    for candidate_key, payload in files_payload.items():
        candidate_norm = _normalize_path(candidate_key)
        if candidate_norm.endswith(module_norm):
            return payload
    return None


class _FunctionCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.stack: list[str] = []
        self.functions: list[tuple[str, int, int]] = []

    def _collect_fn(self, node: ast.AST, fn_name: str) -> None:
        end_line = getattr(node, "end_lineno", None) or getattr(node, "lineno", 0)
        full_name = ".".join(self.stack + [fn_name])
        self.functions.append((full_name, int(node.lineno), int(end_line)))

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._collect_fn(node, node.name)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._collect_fn(node, node.name)
        self.generic_visit(node)


def _compute_function_coverage(
    file_path: Path, executed_lines: set[int]
) -> list[FunctionCoverage]:
    source = file_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    collector = _FunctionCollector()
    collector.visit(tree)
    functions: list[FunctionCoverage] = []
    for name, start_line, end_line in collector.functions:
        line_range = range(start_line, end_line + 1)
        covered = any(line in executed_lines for line in line_range)
        functions.append(
            FunctionCoverage(
                name=name,
                start_line=start_line,
                end_line=end_line,
                covered=covered,
            )
        )
    return functions


def main() -> int:
    args = _parse_args()
    try:
        overrides = _parse_threshold_overrides(args.threshold)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    thresholds = {} if args.no_default_thresholds else dict(DEFAULT_THRESHOLDS)
    thresholds.update(overrides)
    if not thresholds:
        print(
            "Error: no thresholds configured. Provide --threshold entries.",
            file=sys.stderr,
        )
        return 2

    try:
        coverage = _load_coverage_json(args.coverage_json)
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    files_payload = coverage.get("files")
    if not isinstance(files_payload, dict):
        print("Error: coverage JSON missing 'files' map", file=sys.stderr)
        return 2

    repo_root = args.repo_root.resolve()
    failing_modules: list[str] = []
    result_payload: dict[str, dict] = {}

    print("Critical module coverage gates:")
    for module_path, threshold in sorted(thresholds.items()):
        payload = _find_file_payload(files_payload, module_path)
        module_result = {
            "threshold_percent": threshold,
            "actual_percent": None,
            "meets_threshold": False,
            "uncovered_functions": [],
            "error": None,
        }
        if payload is None:
            msg = "missing from coverage report"
            print(f"- FAIL {module_path}: {msg}")
            module_result["error"] = msg
            failing_modules.append(module_path)
            result_payload[module_path] = module_result
            continue

        summary = payload.get("summary", {})
        percent = float(summary.get("percent_covered", 0.0))
        module_result["actual_percent"] = percent
        module_result["meets_threshold"] = percent >= threshold

        module_file = (repo_root / module_path).resolve()
        try:
            executed_lines = {int(x) for x in payload.get("executed_lines", [])}
            functions = _compute_function_coverage(module_file, executed_lines)
        except Exception as exc:  # pragma: no cover - defensive report path
            module_result["error"] = f"function coverage analysis error: {exc}"
            functions = []

        uncovered = [
            {
                "name": fn.name,
                "line": fn.start_line,
            }
            for fn in functions
            if not fn.covered
        ]
        module_result["uncovered_functions"] = uncovered

        status = "PASS" if module_result["meets_threshold"] else "FAIL"
        print(f"- {status} {module_path}: {percent:.2f}% (threshold {threshold:.2f}%)")
        if uncovered:
            preview = ", ".join(
                f"{item['name']}@L{item['line']}" for item in uncovered[:8]
            )
            suffix = " ..." if len(uncovered) > 8 else ""
            print(f"    uncovered functions: {preview}{suffix}")

        if not module_result["meets_threshold"]:
            failing_modules.append(module_path)
        result_payload[module_path] = module_result

    output = {
        "status": "passed" if not failing_modules else "failed",
        "failing_modules": failing_modules,
        "modules": result_payload,
        "coverage_json": str(args.coverage_json.resolve()),
    }
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(json.dumps(output, indent=2), encoding="utf-8")

    if failing_modules:
        print("\nCoverage gate failed for:")
        for module in failing_modules:
            print(f"- {module}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
