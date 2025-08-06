from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

import pytest

from main import handle_toggle_secret_mode
from seedpass.core.manager import PasswordManager
from helpers import create_vault, TEST_SEED, TEST_PASSWORD
from utils.fingerprint import generate_fingerprint


def test_add_new_fingerprint_initializes_managers(monkeypatch, tmp_path):
    pm = PasswordManager.__new__(PasswordManager)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    pm.initialize_fingerprint_manager()
    called = {}

    def fake_setup_existing_seed(method="paste"):
        pm.current_fingerprint = "fp1"
        pm.fingerprint_manager.current_fingerprint = "fp1"
        pm.fingerprint_dir = tmp_path / "fp1"
        pm.fingerprint_dir.mkdir()
        return "fp1"

    monkeypatch.setattr(pm, "setup_existing_seed", fake_setup_existing_seed)
    monkeypatch.setattr(
        pm, "initialize_managers", lambda: called.setdefault("init", True)
    )
    monkeypatch.setattr("builtins.input", lambda *a: "1")
    pm.config_manager = None
    pm.add_new_fingerprint()
    assert called.get("init") is True


def test_toggle_secret_mode_after_profile_creation(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        vault, enc_mgr = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
        pm = PasswordManager.__new__(PasswordManager)
        pm.vault = vault
        pm.encryption_manager = enc_mgr
        pm.fingerprint_dir = tmp_path
        pm.current_fingerprint = generate_fingerprint(TEST_SEED)
        pm.secret_mode_enabled = False
        pm.clipboard_clear_delay = 45
        pm.config_manager = None

        inputs = iter(["y", "10"])
        monkeypatch.setattr("builtins.input", lambda *a: next(inputs))
        handle_toggle_secret_mode(pm)

        assert pm.secret_mode_enabled is True
        assert pm.clipboard_clear_delay == 10
        assert pm.config_manager is not None
        cfg = pm.config_manager.load_config(require_pin=False)
        assert cfg["secret_mode_enabled"] is True
        assert cfg["clipboard_clear_delay"] == 10
