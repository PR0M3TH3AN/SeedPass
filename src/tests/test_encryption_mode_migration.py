import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

import bcrypt
import pytest

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.entry_management import EntryManager
from password_manager.config_manager import ConfigManager
from password_manager.vault import Vault
from password_manager.manager import PasswordManager
from utils.key_derivation import EncryptionMode


TRANSITIONS = [
    (EncryptionMode.SEED_ONLY, EncryptionMode.SEED_PLUS_PW),
    (EncryptionMode.SEED_ONLY, EncryptionMode.PW_ONLY),
    (EncryptionMode.SEED_PLUS_PW, EncryptionMode.SEED_ONLY),
    (EncryptionMode.SEED_PLUS_PW, EncryptionMode.PW_ONLY),
    (EncryptionMode.PW_ONLY, EncryptionMode.SEED_ONLY),
    (EncryptionMode.PW_ONLY, EncryptionMode.SEED_PLUS_PW),
]


@pytest.mark.parametrize("start_mode,new_mode", TRANSITIONS)
def test_encryption_mode_migration(monkeypatch, start_mode, new_mode):
    with TemporaryDirectory() as tmpdir:
        fp = Path(tmpdir)
        vault, enc_mgr = create_vault(fp, TEST_SEED, TEST_PASSWORD, start_mode)
        entry_mgr = EntryManager(vault, fp)
        cfg_mgr = ConfigManager(vault, fp)

        vault.save_index({"passwords": {}})
        cfg_mgr.save_config(
            {
                "relays": [],
                "pin_hash": "",
                "password_hash": bcrypt.hashpw(
                    TEST_PASSWORD.encode(), bcrypt.gensalt()
                ).decode(),
                "encryption_mode": start_mode.value,
            }
        )

        pm = PasswordManager.__new__(PasswordManager)
        pm.encryption_manager = enc_mgr
        pm.entry_manager = entry_mgr
        pm.config_manager = cfg_mgr
        pm.vault = vault
        pm.password_generator = SimpleNamespace(encryption_manager=enc_mgr)
        pm.fingerprint_dir = fp
        pm.current_fingerprint = "fp"
        pm.parent_seed = TEST_SEED
        pm.encryption_mode = start_mode
        pm.nostr_client = SimpleNamespace(publish_snapshot=lambda *a, **k: None)

        monkeypatch.setattr(
            "password_manager.manager.prompt_existing_password",
            lambda *_: TEST_PASSWORD,
        )
        monkeypatch.setattr(
            "password_manager.manager.NostrClient",
            lambda *a, **kw: SimpleNamespace(publish_snapshot=lambda *a, **k: None),
        )

        pm.change_encryption_mode(new_mode)

        assert pm.encryption_mode is new_mode
        cfg = cfg_mgr.load_config(require_pin=False)
        assert cfg["encryption_mode"] == new_mode.value

        pm.lock_vault()

        monkeypatch.setattr(
            "password_manager.manager.prompt_existing_password",
            lambda *_: TEST_PASSWORD,
        )
        monkeypatch.setattr(PasswordManager, "initialize_bip85", lambda self: None)
        monkeypatch.setattr(PasswordManager, "initialize_managers", lambda self: None)

        pm.unlock_vault()

        assert pm.parent_seed == TEST_SEED
        assert not pm.locked
        assert pm.encryption_mode is new_mode
        assert pm.vault.load_index()["passwords"] == {}
        assert pm.verify_password(TEST_PASSWORD)
