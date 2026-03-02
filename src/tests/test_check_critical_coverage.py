from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


def _load_module():
    repo_root = Path(__file__).resolve().parents[2]
    script_path = repo_root / "scripts" / "check_critical_coverage.py"
    spec = importlib.util.spec_from_file_location(
        "check_critical_coverage", script_path
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


coverage_gate = _load_module()


def test_default_thresholds_include_tui2_service_module():
    assert coverage_gate.DEFAULT_THRESHOLDS["src/seedpass/core/api.py"] == 85.0


def test_parse_threshold_overrides_valid():
    parsed = coverage_gate._parse_threshold_overrides(
        ["src/main.py=40", "src/seedpass/core/manager.py=55.5"]
    )
    assert parsed["src/main.py"] == 40.0
    assert parsed["src/seedpass/core/manager.py"] == 55.5


@pytest.mark.parametrize(
    "value",
    [
        "src/main.py",
        "src/main.py=abc",
        "src/main.py=-1",
        "src/main.py=101",
        "=50",
    ],
)
def test_parse_threshold_overrides_invalid(value):
    with pytest.raises(ValueError):
        coverage_gate._parse_threshold_overrides([value])


def test_find_file_payload_accepts_absolute_path_suffix():
    files_payload = {
        "/tmp/work/src/main.py": {"summary": {"percent_covered": 50.0}},
        "/tmp/work/src/seedpass/core/manager.py": {
            "summary": {"percent_covered": 60.0}
        },
    }
    payload = coverage_gate._find_file_payload(files_payload, "src/main.py")
    assert payload == {"summary": {"percent_covered": 50.0}}


def test_compute_function_coverage_reports_uncovered(tmp_path):
    module_file = tmp_path / "example.py"
    module_file.write_text(
        "\n".join(
            [
                "def covered():",
                "    return 1",
                "",
                "def uncovered():",
                "    return 2",
                "",
                "class A:",
                "    def method(self):",
                "        return 3",
            ]
        ),
        encoding="utf-8",
    )
    coverage = coverage_gate._compute_function_coverage(
        module_file, executed_lines={1, 2}
    )
    by_name = {item.name: item for item in coverage}
    assert by_name["covered"].covered is True
    assert by_name["uncovered"].covered is False
    assert by_name["A.method"].covered is False
