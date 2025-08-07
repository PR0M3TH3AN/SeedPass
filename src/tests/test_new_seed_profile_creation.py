import pytest
from pathlib import Path
from tempfile import TemporaryDirectory

from seedpass.core.manager import PasswordManager
from utils.fingerprint_manager import FingerprintManager
from utils.fingerprint import generate_fingerprint

VALID_SEED = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


def setup_pm(tmp_path, monkeypatch):
    pm = PasswordManager.__new__(PasswordManager)
    pm.fingerprint_manager = FingerprintManager(tmp_path)
    pm.config_manager = type("Cfg", (), {"get_kdf_iterations": lambda self: 1})()
    monkeypatch.setattr("seedpass.core.manager.prompt_for_password", lambda: "pw")
    monkeypatch.setattr("seedpass.core.manager.derive_index_key", lambda seed: b"idx")
    monkeypatch.setattr(
        "seedpass.core.manager.derive_key_from_password", lambda *a, **k: b"k"
    )

    class DummyEnc:
        def __init__(self, *a, **k):
            pass

        def encrypt_parent_seed(self, seed):
            pass

    monkeypatch.setattr("seedpass.core.manager.EncryptionManager", DummyEnc)
    monkeypatch.setattr("seedpass.core.manager.Vault", lambda *a, **k: object())
    monkeypatch.setattr(
        "seedpass.core.manager.ConfigManager", lambda **k: pm.config_manager
    )
    monkeypatch.setattr(pm, "initialize_bip85", lambda: None)
    monkeypatch.setattr(pm, "initialize_managers", lambda: None)
    monkeypatch.setattr(pm, "start_background_sync", lambda: None)
    monkeypatch.setattr(pm, "store_hashed_password", lambda pw: None)
    return pm


def test_generate_new_seed_creates_profile(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        pm = setup_pm(tmp_path, monkeypatch)
        monkeypatch.setattr(pm, "generate_bip85_seed", lambda: VALID_SEED)
        monkeypatch.setattr("seedpass.core.manager.confirm_action", lambda *_: True)

        fingerprint = pm.generate_new_seed()

        assert fingerprint == generate_fingerprint(VALID_SEED)
        assert pm.fingerprint_manager.list_fingerprints() == [fingerprint]
