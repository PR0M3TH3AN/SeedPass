import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch, AsyncMock

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.entry_management import EntryManager
from password_manager.config_manager import ConfigManager
from password_manager.backup import BackupManager
from password_manager.vault import Vault
from password_manager.manager import PasswordManager, EncryptionMode


def test_change_password_triggers_nostr_backup(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        fp = Path(tmpdir)
        vault, enc_mgr = create_vault(fp, TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, fp)
        backup_mgr = BackupManager(fp, cfg_mgr)
        entry_mgr = EntryManager(vault, backup_mgr)

        pm = PasswordManager.__new__(PasswordManager)
        pm.encryption_mode = EncryptionMode.SEED_ONLY
        pm.encryption_manager = enc_mgr
        pm.entry_manager = entry_mgr
        pm.config_manager = cfg_mgr
        pm.vault = vault
        pm.password_generator = SimpleNamespace(encryption_manager=enc_mgr)
        pm.fingerprint_dir = fp
        pm.current_fingerprint = "fp"
        pm.parent_seed = TEST_SEED
        pm.store_hashed_password = lambda pw: None
        pm.verify_password = lambda pw: True

        monkeypatch.setattr(
            "password_manager.manager.prompt_existing_password", lambda *_: "old"
        )
        monkeypatch.setattr(
            "password_manager.manager.prompt_for_password", lambda: "new"
        )

        with patch("password_manager.manager.NostrClient") as MockClient:
            mock_instance = MockClient.return_value
            mock_instance.publish_snapshot = AsyncMock(return_value=(None, "abcd"))
            pm.nostr_client = mock_instance
            pm.change_password()
            mock_instance.publish_snapshot.assert_called_once()
