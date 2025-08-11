import time
from types import SimpleNamespace

import pytest
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))
import main
from utils.fingerprint_manager import FingerprintManager
from helpers import TEST_SEED


def test_profile_deletion_stops_sync(monkeypatch, tmp_path):
    fm = FingerprintManager(tmp_path)
    fp = fm.add_fingerprint(TEST_SEED)

    calls = {"post": 0, "cleanup": 0}

    def fake_post(_pm):
        calls["post"] += 1

    monkeypatch.setattr(main, "handle_post_to_nostr", fake_post)
    monkeypatch.setattr("builtins.input", lambda *_: "1")
    monkeypatch.setattr(main, "confirm_action", lambda *_: True)

    pm = SimpleNamespace(
        fingerprint_manager=fm,
        current_fingerprint=fp,
        is_dirty=False,
        last_update=time.time(),
        last_activity=time.time(),
        nostr_client=SimpleNamespace(close_client_pool=lambda: None),
        handle_add_password=lambda: None,
        handle_retrieve_entry=lambda: None,
        handle_modify_entry=lambda: None,
        update_activity=lambda: None,
        lock_vault=lambda: None,
        unlock_vault=lambda: None,
        start_background_sync=lambda: None,
        start_background_relay_check=lambda: None,
        cleanup=lambda: calls.__setitem__("cleanup", calls["cleanup"] + 1),
    )

    main.handle_post_to_nostr(pm)
    assert calls["post"] == 1

    with pytest.raises(SystemExit):
        main.handle_remove_fingerprint(pm)

    assert calls["post"] == 1
    assert calls["cleanup"] == 1
    pm.current_fingerprint = fm.current_fingerprint
    assert pm.current_fingerprint is None
    assert pm.is_dirty is False
