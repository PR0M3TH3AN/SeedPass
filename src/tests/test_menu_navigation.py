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
        handle_add_password=lambda: calls.append("add"),
        handle_add_totp=lambda: calls.append("totp"),
        handle_add_ssh_key=lambda: calls.append("ssh"),
        handle_add_seed=lambda: calls.append("seed"),
        handle_add_nostr_key=lambda: calls.append("nostr"),
        handle_add_pgp=lambda: calls.append("pgp"),
        handle_retrieve_entry=lambda: calls.append("retrieve"),
        handle_search_entries=lambda: calls.append("search"),
        handle_list_entries=lambda: calls.append("list"),
        handle_modify_entry=lambda: calls.append("modify"),
        handle_display_totp_codes=lambda: calls.append("show_totp"),
        handle_view_archived_entries=lambda: calls.append("view_archived"),
        update_activity=lambda: None,
        lock_vault=lambda: None,
        unlock_vault=lambda: None,
        start_background_sync=lambda: None,
        start_background_relay_check=lambda: None,
    )


def test_navigate_all_main_menu_options(monkeypatch):
    calls = []
    pm = _make_pm(calls)
    # Sequence through all main menu options then exit
    inputs = iter(["1", "2", "3", "4", "5", "6", "7", "8", ""])
    monkeypatch.setattr(main, "timed_input", lambda *_: next(inputs))
    # Submenus immediately return
    monkeypatch.setattr("builtins.input", lambda *_: "")
    monkeypatch.setattr(main, "handle_settings", lambda *_: calls.append("settings"))
    with pytest.raises(SystemExit):
        main.display_menu(pm, sync_interval=1000, inactivity_timeout=1000)
    assert calls == [
        "retrieve",
        "search",
        "list",
        "modify",
        "show_totp",
        "settings",
        "view_archived",
    ]
