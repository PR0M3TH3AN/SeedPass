import time
from types import SimpleNamespace
from pathlib import Path
import pytest

import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

import main


def test_inactivity_triggers_lock(monkeypatch):
    locked = {"locked": False, "unlocked": False}

    def update_activity():
        pm.last_activity = time.time()

    def lock_vault():
        locked["locked"] = True

    def unlock_vault():
        locked["unlocked"] = True
        update_activity()

    pm = SimpleNamespace(
        is_dirty=False,
        last_update=time.time(),
        last_activity=time.time() - 1.0,
        nostr_client=SimpleNamespace(close_client_pool=lambda: None),
        handle_add_password=lambda: None,
        handle_retrieve_entry=lambda: None,
        handle_modify_entry=lambda: None,
        update_activity=update_activity,
        lock_vault=lock_vault,
        unlock_vault=unlock_vault,
        start_background_sync=lambda: None,
        start_background_relay_check=lambda: None,
    )

    monkeypatch.setattr(main, "timed_input", lambda *_: "")

    with pytest.raises(SystemExit):
        main.display_menu(pm, sync_interval=1000, inactivity_timeout=0.1)

    assert locked["locked"]
    assert locked["unlocked"]


def test_input_timeout_triggers_lock(monkeypatch):
    """Ensure locking occurs if no input is provided before timeout."""
    locked = {"locked": 0, "unlocked": 0}

    def update_activity():
        pm.last_activity = time.time()

    def lock_vault():
        locked["locked"] += 1

    def unlock_vault():
        locked["unlocked"] += 1
        update_activity()

    pm = SimpleNamespace(
        is_dirty=False,
        last_update=time.time(),
        last_activity=time.time(),
        nostr_client=SimpleNamespace(close_client_pool=lambda: None),
        handle_add_password=lambda: None,
        handle_retrieve_entry=lambda: None,
        handle_modify_entry=lambda: None,
        update_activity=update_activity,
        lock_vault=lock_vault,
        unlock_vault=unlock_vault,
        start_background_sync=lambda: None,
        start_background_relay_check=lambda: None,
    )

    responses = iter([TimeoutError(), ""])

    def fake_input(*_args, **_kwargs):
        val = next(responses)
        if isinstance(val, Exception):
            raise val
        return val

    monkeypatch.setattr(main, "timed_input", fake_input)

    with pytest.raises(SystemExit):
        main.display_menu(pm, sync_interval=1000, inactivity_timeout=0.1)

    assert locked["locked"] == 1
    assert locked["unlocked"] == 1


def test_update_activity_checks_timeout(monkeypatch):
    """AuthGuard in update_activity locks the vault after inactivity."""
    import seedpass.core.manager as manager

    now = {"val": 0.0}
    monkeypatch.setattr(manager.time, "time", lambda: now["val"])

    pm = manager.PasswordManager.__new__(manager.PasswordManager)
    pm.inactivity_timeout = 0.5
    pm.last_activity = 0.0
    pm.locked = False
    called = {}

    def lock():
        called["locked"] = True
        pm.locked = True

    pm.lock_vault = lock
    pm.auth_guard = manager.AuthGuard(pm, time_fn=lambda: now["val"])

    now["val"] = 0.4
    pm.update_activity()
    assert not called

    now["val"] = 1.1
    pm.update_activity()
    assert called["locked"] is True
