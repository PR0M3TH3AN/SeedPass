import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.entry_management import EntryManager
from password_manager.backup import BackupManager
from password_manager.manager import PasswordManager, EncryptionMode
from password_manager.config_manager import ConfigManager


class FakeNostrClient:
    def __init__(self, *args, **kwargs):
        self.published = []

    def publish_snapshot(self, data: bytes):
        self.published.append(data)
        return None, "abcd"


def test_handle_display_totp_codes(monkeypatch, capsys):
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
        pm.nostr_client = FakeNostrClient()
        pm.fingerprint_dir = tmp_path
        pm.is_dirty = False
        pm.secret_mode_enabled = False

        entry_mgr.add_totp("Example", TEST_SEED)

        monkeypatch.setattr(pm.entry_manager, "get_totp_code", lambda *a, **k: "123456")
        monkeypatch.setattr(
            pm.entry_manager, "get_totp_time_remaining", lambda *a, **k: 30
        )

        # interrupt the loop after first iteration
        monkeypatch.setattr(
            "password_manager.manager.timed_input",
            lambda *a, **k: (_ for _ in ()).throw(KeyboardInterrupt()),
        )

        pm.handle_display_totp_codes()
        out = capsys.readouterr().out
        assert "Generated 2FA Codes" in out
        assert "[0] Example" in out
        assert "123456" in out


def test_display_totp_codes_excludes_archived(monkeypatch, capsys):
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
        pm.nostr_client = FakeNostrClient()
        pm.fingerprint_dir = tmp_path
        pm.is_dirty = False
        pm.secret_mode_enabled = False

        entry_mgr.add_totp("Visible", TEST_SEED)
        entry_mgr.add_totp("Hidden", TEST_SEED)
        entry_mgr.modify_entry(1, archived=True)

        monkeypatch.setattr(pm.entry_manager, "get_totp_code", lambda *a, **k: "123456")
        monkeypatch.setattr(
            pm.entry_manager, "get_totp_time_remaining", lambda *a, **k: 30
        )

        monkeypatch.setattr(
            "password_manager.manager.timed_input",
            lambda *a, **k: (_ for _ in ()).throw(KeyboardInterrupt()),
        )

        pm.handle_display_totp_codes()
        out = capsys.readouterr().out
        assert "Visible" in out
        assert "Hidden" not in out
