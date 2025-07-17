import sys
from types import SimpleNamespace
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass.core.manager import PasswordManager
import seedpass.core.manager as manager_module


def test_switch_fingerprint_triggers_bg_sync(monkeypatch, tmp_path):
    pm = PasswordManager.__new__(PasswordManager)
    fingerprint = "fp1"
    fm = SimpleNamespace(
        list_fingerprints=lambda: [fingerprint],
        current_fingerprint=None,
        get_current_fingerprint_dir=lambda: tmp_path / fingerprint,
    )
    pm.fingerprint_manager = fm
    pm.current_fingerprint = None
    pm.encryption_manager = object()
    pm.config_manager = SimpleNamespace(get_quick_unlock=lambda: False)

    monkeypatch.setattr("builtins.input", lambda *_a, **_k: "1")
    monkeypatch.setattr(
        "seedpass.core.manager.prompt_existing_password", lambda *_a, **_k: "pw"
    )
    monkeypatch.setattr(
        PasswordManager, "setup_encryption_manager", lambda *a, **k: True
    )
    monkeypatch.setattr(PasswordManager, "initialize_bip85", lambda *a, **k: None)
    monkeypatch.setattr(PasswordManager, "initialize_managers", lambda *a, **k: None)
    monkeypatch.setattr("seedpass.core.manager.NostrClient", lambda *a, **kw: object())

    calls = {"count": 0}

    def fake_bg(self=None):
        calls["count"] += 1

    monkeypatch.setattr(PasswordManager, "start_background_sync", fake_bg)

    assert pm.handle_switch_fingerprint()
    assert calls["count"] == 1


def test_exit_managed_account_triggers_bg_sync(monkeypatch, tmp_path):
    pm = PasswordManager.__new__(PasswordManager)
    pm.profile_stack = [("rootfp", tmp_path, "seed")]
    pm.config_manager = SimpleNamespace(get_quick_unlock=lambda: False)

    monkeypatch.setattr(manager_module, "derive_index_key", lambda seed: b"k")
    monkeypatch.setattr(
        manager_module, "EncryptionManager", lambda *a, **kw: SimpleNamespace()
    )
    monkeypatch.setattr(manager_module, "Vault", lambda *a, **kw: SimpleNamespace())
    monkeypatch.setattr(PasswordManager, "initialize_bip85", lambda *a, **kw: None)
    monkeypatch.setattr(PasswordManager, "initialize_managers", lambda *a, **kw: None)
    monkeypatch.setattr(PasswordManager, "update_activity", lambda *a, **kw: None)

    calls = {"count": 0}

    def fake_bg(self=None):
        calls["count"] += 1

    monkeypatch.setattr(PasswordManager, "start_background_sync", fake_bg)

    pm.exit_managed_account()
    assert calls["count"] == 1
