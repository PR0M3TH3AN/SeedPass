import bcrypt
from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import TEST_SEED, TEST_PASSWORD
from utils.fingerprint import generate_fingerprint
from utils.key_derivation import derive_index_key, derive_key_from_password
from seedpass.core.encryption import EncryptionManager
from seedpass.core.vault import Vault
from seedpass.core.config_manager import ConfigManager
from seedpass.core.manager import PasswordManager, EncryptionMode


def test_kdf_iteration_fallback(monkeypatch):
    with TemporaryDirectory() as td:
        tmp = Path(td)
        fp_name = generate_fingerprint(TEST_SEED)
        fp_dir = tmp / fp_name
        fp_dir.mkdir()

        seed_key = derive_key_from_password(TEST_PASSWORD, fp_name, iterations=100_000)
        EncryptionManager(seed_key, fp_dir).encrypt_parent_seed(TEST_SEED)

        index_key = derive_index_key(TEST_SEED)
        enc_mgr = EncryptionManager(index_key, fp_dir)
        vault = Vault(enc_mgr, fp_dir)
        cfg_mgr = ConfigManager(vault, fp_dir)
        cfg = cfg_mgr.load_config(require_pin=False)
        cfg["password_hash"] = bcrypt.hashpw(
            TEST_PASSWORD.encode(), bcrypt.gensalt()
        ).decode()
        cfg["kdf_iterations"] = 100_000
        cfg_mgr.save_config(cfg)

        cfg["kdf_iterations"] = 50_000
        cfg_mgr.save_config(cfg)

        pm = PasswordManager.__new__(PasswordManager)
        pm.encryption_mode = EncryptionMode.SEED_ONLY
        pm.config_manager = cfg_mgr
        pm.fingerprint_dir = fp_dir
        pm.current_fingerprint = fp_name
        pm.verify_password = lambda pw: True

        monkeypatch.setattr(
            "seedpass.core.manager.prompt_existing_password", lambda *_: TEST_PASSWORD
        )

        assert pm.setup_encryption_manager(fp_dir, exit_on_fail=False)
        assert pm.parent_seed == TEST_SEED
        assert cfg_mgr.get_kdf_iterations() == 100_000
