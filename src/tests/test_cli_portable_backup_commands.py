import sys
from pathlib import Path
import runpy

import pytest

sys.path.append(str(Path(__file__).resolve().parents[1]))

import main
from password_manager.manager import PasswordManager


def _run(argv, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["seedpass"] + argv)
    monkeypatch.setattr(main, "load_global_config", lambda: {})
    called = {}

    def fake_init(self, encryption_mode):
        called["init"] = True

    def fake_export(self, dest):
        called["export"] = Path(dest)

    def fake_import(self, src):
        called["import"] = Path(src)

    monkeypatch.setattr(PasswordManager, "__init__", fake_init)
    monkeypatch.setattr(PasswordManager, "handle_export_database", fake_export)
    monkeypatch.setattr(PasswordManager, "handle_import_database", fake_import)

    with pytest.raises(SystemExit):
        runpy.run_module("main", run_name="__main__")

    return called


def test_export_command_invokes_handler(monkeypatch):
    called = _run(["export", "--file", "out.json"], monkeypatch)
    assert called["export"] == Path("out.json")
    assert "import" not in called


def test_import_command_invokes_handler(monkeypatch):
    called = _run(["import", "--file", "backup.json"], monkeypatch)
    assert called["import"] == Path("backup.json")
    assert "export" not in called
