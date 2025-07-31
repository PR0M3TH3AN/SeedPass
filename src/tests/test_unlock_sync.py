import time
import asyncio
import warnings
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

    async def fake_sync(self):
        called["sync"] = True

    monkeypatch.setattr(PasswordManager, "sync_index_from_nostr_async", fake_sync)

    pm.unlock_vault("pw")
    pm.start_background_sync()
    time.sleep(0.05)
    pm.cleanup()

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


def test_start_background_sync_running_loop(monkeypatch):
    pm = PasswordManager.__new__(PasswordManager)
    pm.offline_mode = False
    called = {"init": False, "sync": False}

    async def fake_attempt(self):
        called["init"] = True

    async def fake_sync(self):
        called["sync"] = True

    monkeypatch.setattr(PasswordManager, "attempt_initial_sync_async", fake_attempt)
    monkeypatch.setattr(PasswordManager, "sync_index_from_nostr_async", fake_sync)

    async def runner():
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            pm.start_background_sync()
            await asyncio.sleep(0.01)
        assert not any(issubclass(wi.category, RuntimeWarning) for wi in w)

    asyncio.run(runner())
    pm.cleanup()
    assert called["init"] and called["sync"]
