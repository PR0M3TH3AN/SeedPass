from pathlib import Path
from tempfile import TemporaryDirectory

from main import handle_toggle_quick_unlock
from seedpass.core.manager import PasswordManager
from helpers import create_vault, TEST_SEED, TEST_PASSWORD
from utils.fingerprint import generate_fingerprint


def test_toggle_quick_unlock_after_profile_creation(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        vault, enc_mgr = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
        pm = PasswordManager.__new__(PasswordManager)
        pm.vault = vault
        pm.encryption_manager = enc_mgr
        pm.fingerprint_dir = tmp_path
        pm.current_fingerprint = generate_fingerprint(TEST_SEED)
        pm.config_manager = None

        inputs = iter(["y"])
        monkeypatch.setattr("builtins.input", lambda *a: next(inputs))
        handle_toggle_quick_unlock(pm)

        assert pm.config_manager is not None
        cfg = pm.config_manager.load_config(require_pin=False)
        assert cfg["quick_unlock_enabled"] is True
