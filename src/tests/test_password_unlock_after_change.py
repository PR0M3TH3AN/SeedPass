import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

import bcrypt

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.encryption import EncryptionManager
from password_manager.vault import Vault
from password_manager.entry_management import EntryManager
from password_manager.config_manager import ConfigManager
from password_manager.manager import PasswordManager, EncryptionMode
from utils.key_derivation import derive_index_key, derive_key_from_password

SEED = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


def test_password_change_and_unlock(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        fp = Path(tmpdir)
        old_pw = "oldpw"
        new_pw = "newpw"

        # initial encryption setup
        index_key = derive_index_key(SEED, old_pw, EncryptionMode.SEED_PLUS_PW)
        seed_key = derive_key_from_password(old_pw)
        enc_mgr = EncryptionManager(index_key, fp)
        seed_mgr = EncryptionManager(seed_key, fp)
        vault = Vault(enc_mgr, fp)
        entry_mgr = EntryManager(vault, fp)
        cfg_mgr = ConfigManager(vault, fp)

        vault.save_index({"passwords": {}})
        cfg_mgr.save_config(
            {
                "relays": [],
                "pin_hash": "",
                "password_hash": bcrypt.hashpw(
                    old_pw.encode(), bcrypt.gensalt()
                ).decode(),
            }
        )
        seed_mgr.encrypt_parent_seed(SEED)

        pm = PasswordManager.__new__(PasswordManager)
        pm.encryption_mode = EncryptionMode.SEED_PLUS_PW
        pm.encryption_manager = enc_mgr
        pm.entry_manager = entry_mgr
        pm.config_manager = cfg_mgr
        pm.vault = vault
        pm.password_generator = SimpleNamespace(encryption_manager=enc_mgr)
        pm.fingerprint_dir = fp
        pm.current_fingerprint = "fp"
        pm.parent_seed = SEED
        pm.nostr_client = SimpleNamespace(publish_json_to_nostr=lambda *a, **k: None)

        monkeypatch.setattr(
            "password_manager.manager.prompt_existing_password", lambda *_: old_pw
        )
        monkeypatch.setattr(
            "password_manager.manager.prompt_for_password", lambda: new_pw
        )
        monkeypatch.setattr(
            "password_manager.manager.NostrClient",
            lambda *a, **kw: SimpleNamespace(
                publish_json_to_nostr=lambda *a, **k: None
            ),
        )

        pm.change_password()
        pm.lock_vault()

        monkeypatch.setattr(
            "password_manager.manager.prompt_existing_password", lambda *_: new_pw
        )
        monkeypatch.setattr(PasswordManager, "initialize_bip85", lambda self: None)
        monkeypatch.setattr(PasswordManager, "initialize_managers", lambda self: None)

        pm.unlock_vault()

        assert pm.parent_seed == SEED
        assert pm.verify_password(new_pw)
        assert not pm.locked
