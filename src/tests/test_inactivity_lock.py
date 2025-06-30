import time
from types import SimpleNamespace
from pathlib import Path
import pytest

import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

import main


def test_inactivity_triggers_lock(monkeypatch):
    locked = {"locked": False, "unlocked": False}

    pm = SimpleNamespace(
        is_dirty=False,
        last_update=time.time(),
        last_activity=time.time() - 1.0,
        nostr_client=SimpleNamespace(close_client_pool=lambda: None),
        handle_add_password=lambda: None,
        handle_retrieve_entry=lambda: None,
        handle_modify_entry=lambda: None,
        update_activity=lambda: None,
        lock_vault=lambda: locked.update(locked=True) or None,
        unlock_vault=lambda: locked.update(unlocked=True) or None,
    )

    monkeypatch.setattr("builtins.input", lambda _: "5")

    with pytest.raises(SystemExit):
        main.display_menu(pm, sync_interval=1000, inactivity_timeout=0.1)

    assert locked["locked"]
    assert locked["unlocked"]
