from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_module():
    repo_root = Path(__file__).resolve().parents[2]
    script_path = repo_root / "scripts" / "check_determinism_suite.py"
    spec = importlib.util.spec_from_file_location(
        "check_determinism_suite", script_path
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = _load_module()


def test_extract_nodeids_filters_noise():
    output = """
<Package tests>
src/tests/test_seed_entry.py::test_seed_phrase_determinism
============================ test session starts ============================
src/tests/test_pgp_entry.py::test_pgp_key_determinism
"""
    nodeids = gate._extract_nodeids(output)
    assert nodeids == [
        "src/tests/test_seed_entry.py::test_seed_phrase_determinism",
        "src/tests/test_pgp_entry.py::test_pgp_key_determinism",
    ]


def test_extract_file_set_normalizes_windows_paths():
    nodeids = [
        r"src\tests\test_seed_entry.py::test_seed_phrase_determinism",
        "src/tests/test_pgp_entry.py::test_pgp_key_determinism",
    ]
    files = gate._extract_file_set(nodeids)
    assert "src/tests/test_seed_entry.py" in files
    assert "src/tests/test_pgp_entry.py" in files
