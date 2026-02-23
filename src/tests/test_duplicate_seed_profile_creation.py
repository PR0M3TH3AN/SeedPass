import pytest
from pathlib import Path
from tempfile import TemporaryDirectory

from seedpass.core.manager import PasswordManager
from utils.fingerprint_manager import FingerprintManager
from utils.fingerprint import generate_fingerprint

VALID_SEED = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


def _setup_pm(tmp_path, monkeypatch):
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
    monkeypatch.setattr("seedpass.core.manager.confirm_action", lambda *_: False)
    return pm


def test_duplicate_seed_profile_creation(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        pm = _setup_pm(tmp_path, monkeypatch)

        fp1 = pm._finalize_existing_seed(VALID_SEED, password="pw")
        assert fp1 == generate_fingerprint(VALID_SEED)
        assert pm.fingerprint_manager.list_fingerprints() == [fp1]

        fp2 = pm._finalize_existing_seed(VALID_SEED, password="pw")
        assert fp2 is None
        assert pm.fingerprint_manager.list_fingerprints() == [fp1]
