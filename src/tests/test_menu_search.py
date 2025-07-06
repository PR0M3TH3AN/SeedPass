import time
from types import SimpleNamespace
from pathlib import Path
import sys
import pytest

sys.path.append(str(Path(__file__).resolve().parents[1]))

import main


def _make_pm(called):
    pm = SimpleNamespace(
        is_dirty=False,
        last_update=time.time(),
        last_activity=time.time(),
        nostr_client=SimpleNamespace(close_client_pool=lambda: None),
        handle_add_password=lambda: None,
        handle_add_totp=lambda: None,
        handle_retrieve_entry=lambda: None,
        handle_search_entries=lambda: called.append("search"),
        handle_modify_entry=lambda: None,
        update_activity=lambda: None,
        lock_vault=lambda: None,
        unlock_vault=lambda: None,
    )
    return pm


def test_menu_search_option(monkeypatch):
    called = []
    pm = _make_pm(called)
    inputs = iter(["3", ""])
    monkeypatch.setattr(main, "timed_input", lambda *_: next(inputs))
    monkeypatch.setattr("builtins.input", lambda *_: "query")
    with pytest.raises(SystemExit):
        main.display_menu(pm, sync_interval=1000, inactivity_timeout=1000)
    assert called == ["search"]
