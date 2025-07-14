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
    if msg is not None:
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
    monkeypatch.setattr(main, "clear_header_with_notification", lambda *a, **k: None)
    monkeypatch.setattr(main, "timed_input", lambda *a, **k: "")
    with pytest.raises(SystemExit):
        main.display_menu(pm, sync_interval=1000, inactivity_timeout=1000)
    out = capsys.readouterr().out
    assert "\x1b[F\x1b[2K" in out
    assert out.count("hello") == 1


def test_display_menu_reuses_notification_line(monkeypatch, capsys):
    pm = _make_pm(None)
    msgs = iter(["first", "second"])
    monkeypatch.setattr(main, "_display_live_stats", lambda *_: None)
    monkeypatch.setattr(main, "clear_header_with_notification", lambda *a, **k: None)
    inputs = iter(["9", ""])
    monkeypatch.setattr(main, "timed_input", lambda *a, **k: next(inputs))
    monkeypatch.setattr(main, "drain_notifications", lambda _pm: next(msgs, None))
    with pytest.raises(SystemExit):
        main.display_menu(pm, sync_interval=1000, inactivity_timeout=1000)
    out = capsys.readouterr().out
    assert out.count("first") == 1
    assert out.count("second") == 1
    assert out.count("Select an option:") == 2
