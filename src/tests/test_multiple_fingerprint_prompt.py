import importlib
from pathlib import Path
from tempfile import TemporaryDirectory

import constants
import seedpass.core.manager as manager_module
from utils.fingerprint_manager import FingerprintManager

from helpers import TEST_SEED

OTHER_SEED = (
    "legal winner thank year wave sausage worth useful legal winner thank yellow"
)


def test_prompt_when_multiple_fingerprints(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        importlib.reload(constants)
        importlib.reload(manager_module)

        fm = FingerprintManager(constants.APP_DIR)
        fp1 = fm.add_fingerprint(TEST_SEED)
        fm.add_fingerprint(OTHER_SEED)

        def init_fm(self):
            self.fingerprint_manager = fm

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

        calls = {"count": 0}

        def fake_input(*args, **kwargs):
            calls["count"] += 1
            return "1"  # select first fingerprint

        monkeypatch.setattr("builtins.input", fake_input)

        pm = manager_module.PasswordManager()
        assert calls["count"] == 1
        assert pm.current_fingerprint == fp1
