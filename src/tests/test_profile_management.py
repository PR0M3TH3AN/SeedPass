import sys
import importlib
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from cryptography.fernet import Fernet

sys.path.append(str(Path(__file__).resolve().parents[1]))


from utils.fingerprint_manager import FingerprintManager
import constants
import password_manager.manager as manager_module
from password_manager.encryption import EncryptionManager
from password_manager.vault import Vault
from password_manager.entry_management import EntryManager


def test_add_and_delete_entry(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        importlib.reload(constants)
        importlib.reload(manager_module)

        pm = manager_module.PasswordManager.__new__(manager_module.PasswordManager)
        pm.fingerprint_manager = FingerprintManager(constants.APP_DIR)
        pm.current_fingerprint = None
        pm.save_and_encrypt_seed = lambda seed, fingerprint_dir: None
        pm.initialize_bip85 = lambda: None
        pm.initialize_managers = lambda: None
        pm.sync_index_from_nostr_if_missing = lambda: None

        seed = "abandon " * 11 + "about"
        monkeypatch.setattr(
            manager_module.PasswordManager, "generate_bip85_seed", lambda self: seed
        )
        monkeypatch.setattr(manager_module, "confirm_action", lambda *_a, **_k: True)
        monkeypatch.setattr("builtins.input", lambda *_a, **_k: "2")

        pm.add_new_fingerprint()

        fingerprint = pm.current_fingerprint
        fingerprint_dir = constants.APP_DIR / fingerprint
        pm.fingerprint_dir = fingerprint_dir

        assert fingerprint_dir.exists()
        assert pm.fingerprint_manager.current_fingerprint == fingerprint

        key = Fernet.generate_key()
        enc_mgr = EncryptionManager(key, fingerprint_dir)
        vault = Vault(enc_mgr, fingerprint_dir)
        entry_mgr = EntryManager(vault, fingerprint_dir)

        pm.encryption_manager = enc_mgr
        pm.vault = vault
        pm.entry_manager = entry_mgr

        index = entry_mgr.add_entry("example.com", 12)
        assert str(index) in vault.load_index()["passwords"]

        published = []
        pm.nostr_client = SimpleNamespace(
            publish_json_to_nostr=lambda data, alt_summary=None: (
                published.append(data) or True
            )
        )

        inputs = iter([str(index)])
        monkeypatch.setattr("builtins.input", lambda *_a, **_k: next(inputs))

        pm.delete_entry()

        assert str(index) not in vault.load_index()["passwords"]
        assert published
