import time
from types import SimpleNamespace
from pathlib import Path
import pytest

import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

import main


def test_auto_sync_triggers_post(monkeypatch):
    pm = SimpleNamespace(
        is_dirty=True,
        last_update=time.time() - 0.2,
        nostr_client=SimpleNamespace(close_client_pool=lambda: None),
        handle_add_password=lambda: None,
        handle_retrieve_entry=lambda: None,
        handle_modify_entry=lambda: None,
    )

    called = False

    def fake_post(manager):
        nonlocal called
        called = True

    monkeypatch.setattr(main, "handle_post_to_nostr", fake_post)
    monkeypatch.setattr("builtins.input", lambda _: "5")

    with pytest.raises(SystemExit):
        main.display_menu(pm, sync_interval=0.1)

    assert called
    assert pm.is_dirty is False
