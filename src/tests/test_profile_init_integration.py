import importlib
import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory

from password_manager.manager import PasswordManager, EncryptionMode


def load_script():
    script_path = (
        Path(__file__).resolve().parents[2] / "scripts" / "generate_test_profile.py"
    )
    spec = importlib.util.spec_from_file_location("generate_test_profile", script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_initialize_profile_and_manager(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        gtp = load_script()

        seed, _mgr, dir_path, fingerprint, cfg_mgr = gtp.initialize_profile("test")

        pm = PasswordManager.__new__(PasswordManager)
        pm.encryption_mode = EncryptionMode.SEED_ONLY
        pm.config_manager = cfg_mgr
        pm.fingerprint_dir = dir_path
        pm.current_fingerprint = fingerprint

        monkeypatch.setattr(
            "password_manager.manager.prompt_existing_password",
            lambda *_: gtp.DEFAULT_PASSWORD,
        )
        monkeypatch.setattr(PasswordManager, "initialize_bip85", lambda self: None)
        monkeypatch.setattr(PasswordManager, "initialize_managers", lambda self: None)

        assert pm.setup_encryption_manager(dir_path, exit_on_fail=False)
        assert pm.parent_seed == seed

        index = pm.vault.load_index()
        config = pm.config_manager.load_config(require_pin=False)
        assert "entries" in index
        assert config["password_hash"]
