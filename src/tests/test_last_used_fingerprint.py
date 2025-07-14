import importlib
from pathlib import Path
from tempfile import TemporaryDirectory

import constants
import password_manager.manager as manager_module
from utils.fingerprint_manager import FingerprintManager
from password_manager.manager import EncryptionMode

from helpers import TEST_SEED


def test_last_used_fingerprint(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        importlib.reload(constants)
        importlib.reload(manager_module)

        fm = FingerprintManager(constants.APP_DIR)
        fp = fm.add_fingerprint(TEST_SEED)
        assert fm.current_fingerprint == fp

        # Ensure persistence on reload
        fm2 = FingerprintManager(constants.APP_DIR)
        assert fm2.current_fingerprint == fp

        def init_fm(self):
            self.fingerprint_manager = fm2

        monkeypatch.setattr(
            manager_module.PasswordManager, "initialize_fingerprint_manager", init_fm
        )
        monkeypatch.setattr(
            manager_module.PasswordManager,
            "setup_encryption_manager",
            lambda *a, **k: True,
        )
        monkeypatch.setattr(
            manager_module.PasswordManager, "initialize_bip85", lambda self: None
        )
        monkeypatch.setattr(
            manager_module.PasswordManager, "initialize_managers", lambda self: None
        )
        monkeypatch.setattr(
            manager_module.PasswordManager,
            "sync_index_from_nostr_if_missing",
            lambda self: None,
        )
        monkeypatch.setattr(
            manager_module.PasswordManager, "verify_password", lambda *a, **k: True
        )
        monkeypatch.setattr(
            "builtins.input",
            lambda *a, **k: (_ for _ in ()).throw(AssertionError("prompted")),
        )

        pm = manager_module.PasswordManager()
        assert pm.current_fingerprint == fp
