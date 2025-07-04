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


def setup_pm(tmp_path):
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
    pm.password_generator = SimpleNamespace(generate_password=lambda l, i: "pw")
    pm.parent_seed = TEST_SEED
    pm.nostr_client = SimpleNamespace()
    pm.fingerprint_dir = tmp_path
    pm.config_manager = cfg_mgr
    pm.secret_mode_enabled = True
    pm.clipboard_clear_delay = 5
    return pm, entry_mgr


def test_password_retrieve_secret_mode(monkeypatch, capsys):
    with TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        pm, entry_mgr = setup_pm(tmp)
        entry_mgr.add_entry("example", 8)

        monkeypatch.setattr("builtins.input", lambda *a, **k: "0")
        called = []
        monkeypatch.setattr(
            "password_manager.manager.copy_to_clipboard",
            lambda text, t: called.append((text, t)),
        )

        pm.handle_retrieve_entry()
        out = capsys.readouterr().out
        assert "Password:" not in out
        assert "copied to clipboard" in out
        assert called == [("pw", 5)]


def test_totp_display_secret_mode(monkeypatch, capsys):
    with TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        pm, entry_mgr = setup_pm(tmp)
        entry_mgr.add_totp("Example", TEST_SEED)

        monkeypatch.setattr(pm.entry_manager, "get_totp_code", lambda *a, **k: "123456")
        monkeypatch.setattr(
            pm.entry_manager, "get_totp_time_remaining", lambda *a, **k: 30
        )
        monkeypatch.setattr(
            "password_manager.manager.select.select",
            lambda *a, **k: (_ for _ in ()).throw(KeyboardInterrupt()),
        )
        called = []
        monkeypatch.setattr(
            "password_manager.manager.copy_to_clipboard",
            lambda text, t: called.append((text, t)),
        )

        pm.handle_display_totp_codes()
        out = capsys.readouterr().out
        assert "123456" not in out
        assert "copied to clipboard" in out
        assert called == [("123456", 5)]


def test_password_retrieve_no_secret_mode(monkeypatch, capsys):
    with TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        pm, entry_mgr = setup_pm(tmp)
        pm.secret_mode_enabled = False
        entry_mgr.add_entry("example", 8)

        monkeypatch.setattr("builtins.input", lambda *a, **k: "0")
        called = []
        monkeypatch.setattr(
            "password_manager.manager.copy_to_clipboard",
            lambda *a, **k: called.append((a, k)),
        )

        pm.handle_retrieve_entry()
        out = capsys.readouterr().out
        assert "Password:" in out
        assert "copied to clipboard" not in out
        assert called == []


def test_totp_display_no_secret_mode(monkeypatch, capsys):
    with TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        pm, entry_mgr = setup_pm(tmp)
        pm.secret_mode_enabled = False
        entry_mgr.add_totp("Example", TEST_SEED)

        monkeypatch.setattr(pm.entry_manager, "get_totp_code", lambda *a, **k: "123456")
        monkeypatch.setattr(
            pm.entry_manager, "get_totp_time_remaining", lambda *a, **k: 30
        )
        monkeypatch.setattr(
            "password_manager.manager.select.select",
            lambda *a, **k: (_ for _ in ()).throw(KeyboardInterrupt()),
        )
        called = []
        monkeypatch.setattr(
            "password_manager.manager.copy_to_clipboard",
            lambda *a, **k: called.append((a, k)),
        )

        pm.handle_display_totp_codes()
        out = capsys.readouterr().out
        assert "123456" in out
        assert "copied to clipboard" not in out
        assert called == []
