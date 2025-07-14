import time
import queue
from types import SimpleNamespace
from pathlib import Path
import sys
import pytest

sys.path.append(str(Path(__file__).resolve().parents[1]))

import main


def _make_pm(msg):
    q = queue.Queue()
    q.put(SimpleNamespace(message=msg, level="INFO"))
    return SimpleNamespace(
        notifications=q,
        is_dirty=False,
        last_update=time.time(),
        last_activity=time.time(),
        nostr_client=SimpleNamespace(close_client_pool=lambda: None),
        handle_add_password=lambda: None,
        handle_retrieve_entry=lambda: None,
        handle_search_entries=lambda: None,
        handle_list_entries=lambda: None,
        handle_modify_entry=lambda: None,
        handle_display_totp_codes=lambda: None,
        update_activity=lambda: None,
        lock_vault=lambda: None,
        unlock_vault=lambda: None,
        start_background_sync=lambda: None,
        start_background_relay_check=lambda: None,
        profile_stack=[],
        current_fingerprint="fp",
    )


def test_display_menu_prints_notifications(monkeypatch, capsys):
    pm = _make_pm("hello")
    monkeypatch.setattr(main, "_display_live_stats", lambda *_: None)
    monkeypatch.setattr(main, "clear_and_print_fingerprint", lambda *a, **k: None)
    monkeypatch.setattr(main, "timed_input", lambda *a, **k: "")
    with pytest.raises(SystemExit):
        main.display_menu(pm, sync_interval=1000, inactivity_timeout=1000)
    out = capsys.readouterr().out
    assert "hello" in out
