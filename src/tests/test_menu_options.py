import time
from types import SimpleNamespace
from pathlib import Path
import sys
import pytest

sys.path.append(str(Path(__file__).resolve().parents[1]))

import main


def _make_pm(calls):
    return SimpleNamespace(
        is_dirty=False,
        last_update=time.time(),
        last_activity=time.time(),
        nostr_client=SimpleNamespace(close_client_pool=lambda: None),
        handle_add_password=lambda: None,
        handle_add_totp=lambda: None,
        handle_retrieve_entry=lambda: None,
        handle_search_entries=lambda: None,
        handle_modify_entry=lambda: None,
        handle_display_totp_codes=lambda: calls.append("totp"),
        update_activity=lambda: None,
        lock_vault=lambda: None,
        unlock_vault=lambda: None,
    )


def test_menu_totp_option(monkeypatch):
    calls = []
    pm = _make_pm(calls)
    inputs = iter(["6", ""])
    monkeypatch.setattr(main, "timed_input", lambda *_: next(inputs))
    monkeypatch.setattr(main, "handle_settings", lambda *_: None)
    with pytest.raises(SystemExit):
        main.display_menu(pm, sync_interval=1000, inactivity_timeout=1000)
    assert calls == ["totp"]


def test_menu_settings_option(monkeypatch):
    calls = []
    pm = _make_pm(calls)
    inputs = iter(["7", ""])
    monkeypatch.setattr(main, "timed_input", lambda *_: next(inputs))
    monkeypatch.setattr(main, "handle_settings", lambda *_: calls.append("settings"))
    with pytest.raises(SystemExit):
        main.display_menu(pm, sync_interval=1000, inactivity_timeout=1000)
    assert calls == ["settings"]
