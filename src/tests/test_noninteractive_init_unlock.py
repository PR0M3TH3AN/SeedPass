import importlib
import bcrypt
from pathlib import Path
from tempfile import TemporaryDirectory

import constants
import password_manager.manager as manager_module
from utils.fingerprint_manager import FingerprintManager
from password_manager.config_manager import ConfigManager
from tests.helpers import TEST_SEED, TEST_PASSWORD, create_vault


def test_init_with_password(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        monkeypatch.setattr(Path, "home", lambda: tmp)
        importlib.reload(constants)
        importlib.reload(manager_module)

        fm = FingerprintManager(constants.APP_DIR)
        fp = fm.add_fingerprint(TEST_SEED)
        dir_path = constants.APP_DIR / fp
        vault, _enc = create_vault(dir_path, TEST_SEED, TEST_PASSWORD)
        cfg = ConfigManager(vault, dir_path)
        cfg.set_password_hash(
            bcrypt.hashpw(TEST_PASSWORD.encode(), bcrypt.gensalt()).decode()
        )
        cfg.set_kdf_iterations(100_000)

        called = {}

        def fake_setup(self, path, pw=None, **_):
            called["password"] = pw
            return True

        monkeypatch.setattr(
            manager_module.PasswordManager, "initialize_bip85", lambda self: None
        )
        monkeypatch.setattr(
            manager_module.PasswordManager, "initialize_managers", lambda self: None
        )
        monkeypatch.setattr(
            manager_module.PasswordManager, "setup_encryption_manager", fake_setup
        )

        pm = manager_module.PasswordManager(fingerprint=fp, password=TEST_PASSWORD)
        assert called["password"] == TEST_PASSWORD


def test_unlock_with_password(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        monkeypatch.setattr(Path, "home", lambda: tmp)
        importlib.reload(constants)
        importlib.reload(manager_module)

        fm = FingerprintManager(constants.APP_DIR)
        fp = fm.add_fingerprint(TEST_SEED)
        dir_path = constants.APP_DIR / fp
        vault, _enc = create_vault(dir_path, TEST_SEED, TEST_PASSWORD)
        cfg = ConfigManager(vault, dir_path)
        cfg.set_password_hash(
            bcrypt.hashpw(TEST_PASSWORD.encode(), bcrypt.gensalt()).decode()
        )

        pm = manager_module.PasswordManager.__new__(manager_module.PasswordManager)
        pm.fingerprint_dir = dir_path
        pm.config_manager = cfg
        pm.locked = True
        called = {}

        def fake_setup(path, pw=None):
            called["password"] = pw

        monkeypatch.setattr(
            manager_module.PasswordManager, "initialize_bip85", lambda self: None
        )
        monkeypatch.setattr(
            manager_module.PasswordManager, "initialize_managers", lambda self: None
        )
        pm.setup_encryption_manager = fake_setup

        pm.unlock_vault(TEST_PASSWORD)
        assert called["password"] == TEST_PASSWORD
