import sys
import importlib
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

sys.path.append(str(Path(__file__).resolve().parents[1]))


def setup_password_manager():
    """Instantiate PasswordManager using a temporary APP_DIR without running __init__."""
    import constants
    import password_manager.manager as manager_module

    # Reload modules so constants use the mocked home directory
    importlib.reload(constants)
    importlib.reload(manager_module)

    pm = manager_module.PasswordManager.__new__(manager_module.PasswordManager)
    pm.encryption_mode = manager_module.EncryptionMode.SEED_ONLY
    pm.fingerprint_manager = manager_module.FingerprintManager(constants.APP_DIR)
    pm.current_fingerprint = None
    pm.save_and_encrypt_seed = lambda seed, fingerprint_dir: None
    return pm, constants


def test_generate_bip85_and_new_seed(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        pm, const = setup_password_manager()

        mnemonic = pm.generate_bip85_seed()
        assert len(mnemonic.split()) == 12

        with patch("password_manager.manager.confirm_action", return_value=True):
            fingerprint = pm.generate_new_seed()

        expected_dir = const.APP_DIR / fingerprint
        assert expected_dir.exists()
        assert expected_dir.is_dir()
