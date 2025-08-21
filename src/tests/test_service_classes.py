from tempfile import TemporaryDirectory
from types import SimpleNamespace
from pathlib import Path

import pytest

from helpers import create_vault, TEST_SEED, TEST_PASSWORD, dummy_nostr_client
from seedpass.core.entry_management import EntryManager
from seedpass.core.backup import BackupManager
from seedpass.core.manager import PasswordManager, EncryptionMode
from seedpass.core.config_manager import ConfigManager
from seedpass.core.entry_service import EntryService
from seedpass.core.profile_service import ProfileService
from constants import DEFAULT_PASSWORD_LENGTH


class FakePasswordGenerator:
    def generate_password(self, length: int, index: int) -> str:
        return f"pw-{index}-{length}"


def _setup_pm(tmp_path: Path, client) -> PasswordManager:
    vault, enc_mgr = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    cfg_mgr = ConfigManager(vault, tmp_path)
    backup_mgr = BackupManager(tmp_path, cfg_mgr)
    entry_mgr = EntryManager(vault, backup_mgr)

    pm = PasswordManager.__new__(PasswordManager)
    pm.encryption_mode = EncryptionMode.SEED_ONLY
    pm.encryption_manager = enc_mgr
    pm.vault = vault
    pm.entry_manager = entry_mgr
    pm.backup_manager = backup_mgr
    pm.password_generator = FakePasswordGenerator()
    pm.parent_seed = TEST_SEED
    pm.nostr_client = client
    pm.fingerprint_dir = tmp_path
    pm.secret_mode_enabled = False
    pm.is_dirty = False
    return pm


def test_entry_service_add_password(monkeypatch, dummy_nostr_client, capsys):
    client, _relay = dummy_nostr_client
    with TemporaryDirectory() as tmpdir:
        pm = _setup_pm(Path(tmpdir), client)
        service = EntryService(pm)
        inputs = iter(
            [
                "a",
                "Example",
                "",
                "",
                "",
                "",
                "n",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
            ]
        )
        monkeypatch.setattr("builtins.input", lambda *a, **k: next(inputs))
        monkeypatch.setattr("seedpass.core.entry_service.pause", lambda *a, **k: None)
        monkeypatch.setattr(pm, "start_background_vault_sync", lambda *a, **k: None)

        service.handle_add_password()
        out = capsys.readouterr().out
        entries = pm.entry_manager.list_entries(verbose=False)
        assert entries == [(0, "Example", "", "", False)]
        assert f"pw-0-{DEFAULT_PASSWORD_LENGTH}" in out


def test_menu_handler_list_entries(monkeypatch, capsys):
    with TemporaryDirectory() as tmpdir:
        pm = _setup_pm(Path(tmpdir), SimpleNamespace())
        pm.entry_manager.add_totp("Example", TEST_SEED)
        pm.entry_manager.add_entry("example.com", 12)
        pm.entry_manager.add_key_value("API entry", "api", "abc123")
        pm.entry_manager.add_managed_account("acct", TEST_SEED)
        inputs = iter(["1", ""])  # list all then exit
        monkeypatch.setattr("builtins.input", lambda *_: next(inputs))
        pm.menu_handler.handle_list_entries()
        out = capsys.readouterr().out
        assert "Example" in out
        assert "example.com" in out
        assert "API" in out
        assert "acct" in out


def test_profile_service_switch(monkeypatch):
    class DummyFingerprintManager:
        def __init__(self):
            self.fingerprints = ["fp1", "fp2"]
            self.current_fingerprint = "fp1"

        def list_fingerprints(self):
            return self.fingerprints

        def display_name(self, fp):
            return fp

        def get_current_fingerprint_dir(self):
            return Path(".")

    pm = PasswordManager.__new__(PasswordManager)
    pm.fingerprint_manager = DummyFingerprintManager()
    pm.current_fingerprint = "fp1"
    pm.setup_encryption_manager = lambda *a, **k: True
    pm.initialize_bip85 = lambda *a, **k: None
    pm.initialize_managers = lambda *a, **k: None
    pm.start_background_sync = lambda *a, **k: None
    pm.nostr_client = SimpleNamespace()
    pm.manifest_id = None
    pm.delta_since = None
    pm.encryption_manager = SimpleNamespace()
    pm.parent_seed = TEST_SEED
    pm.nostr_account_idx = 0

    service = ProfileService(pm)
    monkeypatch.setattr("builtins.input", lambda *_: "2")
    monkeypatch.setattr(
        "seedpass.core.profile_service.prompt_existing_password", lambda *_: "pw"
    )
    monkeypatch.setattr(
        "seedpass.core.manager.NostrClient", lambda *a, **k: SimpleNamespace()
    )

    assert service.handle_switch_fingerprint() is True
    assert pm.current_fingerprint == "fp2"
