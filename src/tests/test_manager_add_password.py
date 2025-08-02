import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

import pytest

from helpers import create_vault, TEST_SEED, TEST_PASSWORD, dummy_nostr_client

sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass.core.entry_management import EntryManager
from seedpass.core.backup import BackupManager
from seedpass.core.manager import PasswordManager, EncryptionMode
from seedpass.core.config_manager import ConfigManager
from constants import DEFAULT_PASSWORD_LENGTH


class FakePasswordGenerator:
    def generate_password(self, length: int, index: int) -> str:  # noqa: D401
        return f"pw-{index}-{length}"


def test_handle_add_password(monkeypatch, dummy_nostr_client, capsys):
    client, _relay = dummy_nostr_client
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
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

        inputs = iter(
            [
                "a",  # advanced mode
                "Example",  # label
                "",  # username
                "",  # url
                "",  # notes
                "",  # tags
                "n",  # add custom field
                "",  # length (default)
                "",  # include special default
                "",  # allowed special default
                "",  # special mode default
                "",  # exclude ambiguous default
                "",  # min uppercase
                "",  # min lowercase
                "",  # min digits
                "",  # min special
            ]
        )
        monkeypatch.setattr("builtins.input", lambda *a, **k: next(inputs))
        monkeypatch.setattr("seedpass.core.manager.pause", lambda *a, **k: None)
        monkeypatch.setattr(pm, "start_background_vault_sync", lambda *a, **k: None)

        pm.handle_add_password()
        out = capsys.readouterr().out

        entries = entry_mgr.list_entries(verbose=False)
        assert entries == [(0, "Example", "", "", False)]

        entry = entry_mgr.retrieve_entry(0)
        assert entry == {
            "label": "Example",
            "length": DEFAULT_PASSWORD_LENGTH,
            "username": "",
            "url": "",
            "archived": False,
            "type": "password",
            "kind": "password",
            "notes": "",
            "custom_fields": [],
            "tags": [],
        }

        assert f"pw-0-{DEFAULT_PASSWORD_LENGTH}" in out


def test_handle_add_password_secret_mode(monkeypatch, dummy_nostr_client, capsys):
    client, _relay = dummy_nostr_client
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
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
        pm.secret_mode_enabled = True
        pm.clipboard_clear_delay = 5
        pm.is_dirty = False

        inputs = iter(
            [
                "a",  # advanced mode
                "Example",  # label
                "",  # username
                "",  # url
                "",  # notes
                "",  # tags
                "n",  # add custom field
                "",  # length (default)
                "",  # include special default
                "",  # allowed special default
                "",  # special mode default
                "",  # exclude ambiguous default
                "",  # min uppercase
                "",  # min lowercase
                "",  # min digits
                "",  # min special
            ]
        )
        monkeypatch.setattr("builtins.input", lambda *a, **k: next(inputs))
        monkeypatch.setattr("seedpass.core.manager.pause", lambda *a, **k: None)
        monkeypatch.setattr(pm, "start_background_vault_sync", lambda *a, **k: None)

        called = []
        monkeypatch.setattr(
            "seedpass.core.manager.copy_to_clipboard",
            lambda text, delay: called.append((text, delay)),
        )

        pm.handle_add_password()
        out = capsys.readouterr().out

        assert f"pw-0-{DEFAULT_PASSWORD_LENGTH}" not in out
        assert "copied to clipboard" in out
        assert called == [(f"pw-0-{DEFAULT_PASSWORD_LENGTH}", 5)]


def test_handle_add_password_quick_mode(monkeypatch, dummy_nostr_client, capsys):
    client, _relay = dummy_nostr_client
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
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

        inputs = iter(
            [
                "q",  # quick mode
                "Example",  # label
                "",  # username
                "",  # url
                "",  # length (default)
                "",  # include special default
            ]
        )
        monkeypatch.setattr("builtins.input", lambda *a, **k: next(inputs))
        monkeypatch.setattr("seedpass.core.manager.pause", lambda *a, **k: None)
        monkeypatch.setattr(pm, "start_background_vault_sync", lambda *a, **k: None)

        pm.handle_add_password()
        out = capsys.readouterr().out

        entries = entry_mgr.list_entries(verbose=False)
        assert entries == [(0, "Example", "", "", False)]

        entry = entry_mgr.retrieve_entry(0)
        assert entry == {
            "label": "Example",
            "length": DEFAULT_PASSWORD_LENGTH,
            "username": "",
            "url": "",
            "archived": False,
            "type": "password",
            "kind": "password",
            "notes": "",
            "custom_fields": [],
            "tags": [],
        }

        assert f"pw-0-{DEFAULT_PASSWORD_LENGTH}" in out
