import bcrypt
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from utils.key_derivation import (
    derive_key_from_password,
    derive_key_from_password_argon2,
    derive_index_key,
)
from seedpass.core.encryption import EncryptionManager
from seedpass.core.vault import Vault
from seedpass.core.config_manager import ConfigManager
from seedpass.core.manager import PasswordManager, EncryptionMode

TEST_SEED = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
TEST_PASSWORD = "pw"


def _setup_profile(tmp: Path, mode: str):
    argon_kwargs = dict(time_cost=1, memory_cost=8, parallelism=1)
    fp = tmp.name
    if mode == "argon2":
        seed_key = derive_key_from_password_argon2(TEST_PASSWORD, fp, **argon_kwargs)
    else:
        seed_key = derive_key_from_password(TEST_PASSWORD, fp, iterations=1)
    EncryptionManager(seed_key, tmp).encrypt_parent_seed(TEST_SEED)

    index_key = derive_index_key(TEST_SEED)
    enc_mgr = EncryptionManager(index_key, tmp)
    vault = Vault(enc_mgr, tmp)
    cfg_mgr = ConfigManager(vault, tmp)
    cfg = cfg_mgr.load_config(require_pin=False)
    cfg["password_hash"] = bcrypt.hashpw(
        TEST_PASSWORD.encode(), bcrypt.gensalt()
    ).decode()
    cfg["kdf_mode"] = mode
    cfg["kdf_iterations"] = 1
    cfg_mgr.save_config(cfg)
    return cfg_mgr


def _make_pm(tmp: Path, cfg: ConfigManager):
    pm = PasswordManager.__new__(PasswordManager)
    pm.encryption_mode = EncryptionMode.SEED_ONLY
    pm.config_manager = cfg
    pm.fingerprint_dir = tmp
    pm.current_fingerprint = tmp.name
    pm.verify_password = lambda pw: True
    return pm


def test_setup_encryption_manager_kdf_modes(monkeypatch):
    with TemporaryDirectory() as td:
        tmp = Path(td)
        argon_kwargs = dict(time_cost=1, memory_cost=8, parallelism=1)
        for mode in ("pbkdf2", "argon2"):
            path = tmp / mode
            path.mkdir()
            cfg = _setup_profile(path, mode)
            pm = _make_pm(path, cfg)
            monkeypatch.setattr(
                "seedpass.core.manager.prompt_existing_password",
                lambda *_: TEST_PASSWORD,
            )
            if mode == "argon2":
                monkeypatch.setattr(
                    "seedpass.core.manager.derive_key_from_password_argon2",
                    lambda pw, fp: derive_key_from_password_argon2(
                        pw, fp, **argon_kwargs
                    ),
                )
            monkeypatch.setattr(PasswordManager, "initialize_bip85", lambda self: None)
            monkeypatch.setattr(
                PasswordManager, "initialize_managers", lambda self: None
            )
            assert pm.setup_encryption_manager(path, exit_on_fail=False)
            assert pm.parent_seed == TEST_SEED
