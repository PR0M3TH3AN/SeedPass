import time
from types import SimpleNamespace
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.manager import PasswordManager


def test_unlock_triggers_sync(monkeypatch, tmp_path):
    pm = PasswordManager.__new__(PasswordManager)
    pm.fingerprint_dir = tmp_path
    pm.setup_encryption_manager = lambda *a, **k: None
    pm.initialize_bip85 = lambda: None
    pm.initialize_managers = lambda: None
    called = {"sync": False}

    def fake_sync(self):
        called["sync"] = True

    monkeypatch.setattr(PasswordManager, "sync_index_from_nostr", fake_sync)

    pm.unlock_vault()
    pm.start_background_sync()
    time.sleep(0.05)

    assert called["sync"]
