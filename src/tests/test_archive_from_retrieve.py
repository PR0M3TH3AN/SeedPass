import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import queue

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.entry_management import EntryManager
from password_manager.backup import BackupManager
from password_manager.manager import PasswordManager, EncryptionMode
from password_manager.config_manager import ConfigManager


class FakePasswordGenerator:
    def generate_password(self, length: int, index: int) -> str:  # noqa: D401
        return "pw"


def test_archive_entry_from_retrieve(monkeypatch):
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
        pm.nostr_client = SimpleNamespace()
        pm.fingerprint_dir = tmp_path
        pm.secret_mode_enabled = False
        pm.notifications = queue.Queue()

        index = entry_mgr.add_entry("example.com", 8)

        inputs = iter([str(index), "a", ""])
        monkeypatch.setattr("builtins.input", lambda *a, **k: next(inputs))

        pm.handle_retrieve_entry()

        assert entry_mgr.retrieve_entry(index)["archived"] is True


def test_restore_entry_from_retrieve(monkeypatch):
    """Archived entries should restore when retrieved and confirmed."""
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
        pm.nostr_client = SimpleNamespace()
        pm.fingerprint_dir = tmp_path
        pm.secret_mode_enabled = False
        pm.notifications = queue.Queue()

        index = entry_mgr.add_entry("example.com", 8)
        entry_mgr.archive_entry(index)

        inputs = iter([str(index), "u", ""])
        monkeypatch.setattr("builtins.input", lambda *a, **k: next(inputs))

        pm.handle_retrieve_entry()

        assert entry_mgr.retrieve_entry(index)["archived"] is False
