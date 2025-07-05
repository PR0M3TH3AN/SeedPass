import sys
import time
from types import SimpleNamespace
from pathlib import Path

import pytest

sys.path.append(str(Path(__file__).resolve().parents[1]))

import main


def _make_pm(called, locked=None):
    if locked is None:
        locked = {"lock": 0, "unlock": 0}

    def add():
        called["add"] = True

    def retrieve():
        called["retrieve"] = True

    def modify():
        called["modify"] = True

    def update():
        pm.last_activity = time.time()

    def lock():
        locked["lock"] += 1

    def unlock():
        locked["unlock"] += 1
        update()

    pm = SimpleNamespace(
        is_dirty=False,
        last_update=time.time(),
        last_activity=time.time(),
        nostr_client=SimpleNamespace(close_client_pool=lambda: None),
        handle_add_password=add,
        handle_add_totp=lambda: None,
        handle_retrieve_entry=retrieve,
        handle_modify_entry=modify,
        update_activity=update,
        lock_vault=lock,
        unlock_vault=unlock,
    )
    return pm, locked


def test_empty_and_non_numeric_choice(monkeypatch, capsys):
    called = {"add": False, "retrieve": False, "modify": False}
    pm, _ = _make_pm(called)
    inputs = iter(["", "abc", "8"])
    monkeypatch.setattr(main, "timed_input", lambda *_: next(inputs))
    with pytest.raises(SystemExit):
        main.display_menu(pm, sync_interval=1000, inactivity_timeout=1000)
    out = capsys.readouterr().out
    assert "No input detected" in out
    assert "Invalid choice. Please select a valid option." in out
    assert not any(called.values())


def test_out_of_range_menu(monkeypatch, capsys):
    called = {"add": False, "retrieve": False, "modify": False}
    pm, _ = _make_pm(called)
    inputs = iter(["9", "8"])
    monkeypatch.setattr(main, "timed_input", lambda *_: next(inputs))
    with pytest.raises(SystemExit):
        main.display_menu(pm, sync_interval=1000, inactivity_timeout=1000)
    out = capsys.readouterr().out
    assert "Invalid choice. Please select a valid option." in out
    assert not any(called.values())


def test_invalid_add_entry_submenu(monkeypatch, capsys):
    called = {"add": False, "retrieve": False, "modify": False}
    pm, _ = _make_pm(called)
    inputs = iter(["1", "8", "7", "8"])
    monkeypatch.setattr(main, "timed_input", lambda *_: next(inputs))
    monkeypatch.setattr("builtins.input", lambda *_: next(inputs))
    with pytest.raises(SystemExit):
        main.display_menu(pm, sync_interval=1000, inactivity_timeout=1000)
    out = capsys.readouterr().out
    assert "Invalid choice." in out
    assert not any(called.values())


def test_inactivity_timeout_loop(monkeypatch, capsys):
    called = {"add": False, "retrieve": False, "modify": False}
    pm, locked = _make_pm(called)
    pm.last_activity = 0
    monkeypatch.setattr(time, "time", lambda: 100.0)
    monkeypatch.setattr(main, "timed_input", lambda *_: "8")
    with pytest.raises(SystemExit):
        main.display_menu(pm, sync_interval=1000, inactivity_timeout=0.1)
    out = capsys.readouterr().out
    assert "Session timed out. Vault locked." in out
    assert locked["lock"] == 1
    assert locked["unlock"] == 1
    assert not any(called.values())
