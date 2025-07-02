import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch, AsyncMock

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.entry_management import EntryManager
from password_manager.config_manager import ConfigManager
from password_manager.vault import Vault
from password_manager.manager import PasswordManager
from utils.key_derivation import EncryptionMode


def test_change_encryption_mode(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        fp = Path(tmpdir)
        vault, enc_mgr = create_vault(
            fp, TEST_SEED, TEST_PASSWORD, EncryptionMode.SEED_ONLY
        )
        entry_mgr = EntryManager(vault, fp)
        cfg_mgr = ConfigManager(vault, fp)
        vault.save_index({"passwords": {}})

        pm = PasswordManager.__new__(PasswordManager)
        pm.encryption_manager = enc_mgr
        pm.entry_manager = entry_mgr
        pm.config_manager = cfg_mgr
        pm.vault = vault
        pm.password_generator = SimpleNamespace(encryption_manager=enc_mgr)
        pm.fingerprint_dir = fp
        pm.current_fingerprint = "fp"
        pm.parent_seed = TEST_SEED
        pm.encryption_mode = EncryptionMode.SEED_ONLY

        monkeypatch.setattr(
            "password_manager.manager.prompt_existing_password",
            lambda *_: TEST_PASSWORD,
        )
        pm.verify_password = lambda pw: True

        with patch("password_manager.manager.NostrClient") as MockClient:
            mock = MockClient.return_value
            mock.publish_snapshot = AsyncMock(return_value=None)
            pm.nostr_client = mock
            pm.change_encryption_mode(EncryptionMode.SEED_PLUS_PW)
            mock.publish_snapshot.assert_called_once()

        assert pm.encryption_mode is EncryptionMode.SEED_PLUS_PW
        assert pm.password_generator.encryption_manager is pm.encryption_manager
        loaded = vault.load_index()
        assert loaded["passwords"] == {}
        cfg = cfg_mgr.load_config(require_pin=False)
        assert cfg["encryption_mode"] == EncryptionMode.SEED_PLUS_PW.value
