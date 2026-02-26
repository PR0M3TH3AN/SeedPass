import sys
import time
from types import SimpleNamespace
from pathlib import Path

import pytest

sys.path.append(str(Path(__file__).resolve().parents[1]))

import main
from seedpass.core.errors import SeedPassError
from utils.password_prompt import PasswordPromptError


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
        handle_add_managed_account=lambda: None,
        handle_retrieve_entry=retrieve,
        handle_modify_entry=modify,
        update_activity=update,
        lock_vault=lock,
        unlock_vault=unlock,
        start_background_sync=lambda: None,
        start_background_relay_check=lambda: None,
    )
    return pm, locked


def test_empty_and_non_numeric_choice(monkeypatch, capsys):
    called = {"add": False, "retrieve": False, "modify": False}
    pm, _ = _make_pm(called)
    inputs = iter(["abc", ""])
    monkeypatch.setattr(main, "timed_input", lambda *_: next(inputs))
    with pytest.raises(SystemExit):
        main.display_menu(pm, sync_interval=1000, inactivity_timeout=1000)
    out = capsys.readouterr().out
    assert "Invalid choice. Please select a valid option." in out
    assert not any(called.values())


def test_out_of_range_menu(monkeypatch, capsys):
    called = {"add": False, "retrieve": False, "modify": False}
    pm, _ = _make_pm(called)
    inputs = iter(["10", ""])
    monkeypatch.setattr(main, "timed_input", lambda *_: next(inputs))
    with pytest.raises(SystemExit):
        main.display_menu(pm, sync_interval=1000, inactivity_timeout=1000)
    out = capsys.readouterr().out
    assert "Invalid choice. Please select a valid option." in out
    assert not any(called.values())


def test_invalid_add_entry_submenu(monkeypatch, capsys):
    called = {"add": False, "retrieve": False, "modify": False}
    pm, _ = _make_pm(called)
    inputs = iter(["1", "9", "", ""])
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
    monkeypatch.setattr(main, "timed_input", lambda *_: "")
    with pytest.raises(SystemExit):
        main.display_menu(pm, sync_interval=1000, inactivity_timeout=0.1)
    out = capsys.readouterr().out
    assert "Session timed out. Vault locked." in out
    assert locked["lock"] == 1
    assert locked["unlock"] == 1
    assert not any(called.values())


def test_inactivity_timeout_unlock_cancelled_stays_in_menu(monkeypatch, capsys):
    called = {"add": False, "retrieve": False, "modify": False}
    pm, locked = _make_pm(called)
    pm.last_activity = 0

    def unlock_fail():
        locked["unlock"] += 1
        pm.last_activity = 100.0
        raise PasswordPromptError("Operation cancelled by user")

    pm.unlock_vault = unlock_fail

    # First iteration: timeout + cancelled unlock. Second: exit cleanly.
    now = iter([100.0, 100.0, 100.0])
    monkeypatch.setattr(time, "time", lambda: next(now))
    monkeypatch.setattr(main, "timed_input", lambda *_: "")

    with pytest.raises(SystemExit):
        main.display_menu(pm, sync_interval=1000, inactivity_timeout=0.1)

    out = capsys.readouterr().out
    assert "Vault remains locked: Operation cancelled by user" in out
    assert locked["lock"] == 1
    assert locked["unlock"] == 1


def test_menu_action_seedpass_error_does_not_crash(monkeypatch, capsys):
    called = {"add": False, "retrieve": False, "modify": False}
    pm, _ = _make_pm(called)

    def fail_retrieve():
        raise SeedPassError("simulated retrieve failure")

    pm.handle_retrieve_entry = fail_retrieve
    inputs = iter(["2", ""])
    monkeypatch.setattr(main, "timed_input", lambda *_: next(inputs))

    with pytest.raises(SystemExit):
        main.display_menu(pm, sync_interval=1000, inactivity_timeout=1000)

    out = capsys.readouterr().out
    assert "Action failed: simulated retrieve failure" in out


def test_menu_action_password_prompt_error_does_not_crash(monkeypatch, capsys):
    called = {"add": False, "retrieve": False, "modify": False}
    pm, _ = _make_pm(called)

    def fail_retrieve():
        raise PasswordPromptError("Operation cancelled by user")

    pm.handle_retrieve_entry = fail_retrieve
    inputs = iter(["2", ""])
    monkeypatch.setattr(main, "timed_input", lambda *_: next(inputs))

    with pytest.raises(SystemExit):
        main.display_menu(pm, sync_interval=1000, inactivity_timeout=1000)

    out = capsys.readouterr().out
    assert "Action cancelled: Operation cancelled by user" in out
