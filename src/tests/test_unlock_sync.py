import time
from types import SimpleNamespace
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass.core.manager import PasswordManager
from seedpass.core import manager as manager_module


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

    pm.unlock_vault("pw")
    pm.start_background_sync()
    time.sleep(0.05)

    assert called["sync"]


def test_quick_unlock_background_sync(monkeypatch, tmp_path):
    pm = PasswordManager.__new__(PasswordManager)
    pm.profile_stack = [("rootfp", tmp_path, "seed")]
    pm.config_manager = SimpleNamespace(get_quick_unlock=lambda: True)

    monkeypatch.setattr(manager_module, "derive_index_key", lambda s: b"k")
    monkeypatch.setattr(
        manager_module, "EncryptionManager", lambda *a, **k: SimpleNamespace()
    )
    monkeypatch.setattr(manager_module, "Vault", lambda *a, **k: SimpleNamespace())

    pm.initialize_bip85 = lambda: None
    pm.initialize_managers = lambda: None
    pm.update_activity = lambda: None

    called = {"bg": False}

    def fake_bg():
        called["bg"] = True

    pm.start_background_sync = fake_bg

    pm.exit_managed_account()

    assert called["bg"]
