from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.entry_management import EntryManager
from password_manager.backup import BackupManager
from password_manager.manager import PasswordManager, EncryptionMode
from password_manager.config_manager import ConfigManager


def test_handle_list_entries(monkeypatch, capsys):
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
        pm.nostr_client = SimpleNamespace()
        pm.fingerprint_dir = tmp_path

        entry_mgr.add_totp("Example", TEST_SEED)
        entry_mgr.add_entry("example.com", 12)
        entry_mgr.add_key_value("API", "abc123")
        entry_mgr.add_managed_account("acct", TEST_SEED)

        inputs = iter(["1", ""])  # list all, then exit
        monkeypatch.setattr("builtins.input", lambda *_: next(inputs))

        pm.handle_list_entries()
        out = capsys.readouterr().out
        assert "Example" in out
        assert "example.com" in out
        assert "API" in out
        assert "acct" in out


def test_list_entries_show_details(monkeypatch, capsys):
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
        pm.parent_seed = TEST_SEED
        pm.nostr_client = SimpleNamespace()
        pm.fingerprint_dir = tmp_path
        pm.secret_mode_enabled = False

        entry_mgr.add_totp("Example", TEST_SEED)
        entry_mgr.add_key_value("API", "val")
        entry_mgr.add_managed_account("acct", TEST_SEED)

        monkeypatch.setattr(pm.entry_manager, "get_totp_code", lambda *a, **k: "123456")
        monkeypatch.setattr(
            pm.entry_manager, "get_totp_time_remaining", lambda *a, **k: 1
        )
        monkeypatch.setattr("password_manager.manager.time.sleep", lambda *a, **k: None)
        monkeypatch.setattr(
            "password_manager.manager.timed_input",
            lambda *a, **k: "b",
        )

        inputs = iter(["1", "0"])
        monkeypatch.setattr("builtins.input", lambda *_: next(inputs))

        pm.handle_list_entries()
        out = capsys.readouterr().out
        assert "Label: Example" in out
        assert "Period: 30s" in out
        assert "API" in out
        assert "acct" in out


def test_show_entry_details_by_index(monkeypatch):
    """Ensure entry details screen triggers expected calls."""
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
        pm.nostr_client = SimpleNamespace()
        pm.fingerprint_dir = tmp_path

        index = entry_mgr.add_entry("example.com", 12)

        header_calls = []
        monkeypatch.setattr(
            "password_manager.manager.clear_header_with_notification",
            lambda *a, **k: header_calls.append(True),
        )
        action_calls = []
        monkeypatch.setattr(
            pm,
            "_entry_actions_menu",
            lambda *a, **k: action_calls.append(True),
        )
        monkeypatch.setattr("password_manager.manager.pause", lambda *a, **k: None)

        pm.show_entry_details_by_index(index)

        assert len(header_calls) == 1
        assert len(action_calls) == 1
