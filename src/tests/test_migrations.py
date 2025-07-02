import sys
from pathlib import Path
import pytest
from cryptography.fernet import Fernet

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.encryption import EncryptionManager
from password_manager.vault import Vault
from password_manager.migrations import LATEST_VERSION


def setup(tmp_path: Path):
    key = Fernet.generate_key()
    enc_mgr = EncryptionManager(key, tmp_path)
    vault = Vault(enc_mgr, tmp_path)
    return enc_mgr, vault


def test_migrate_v0_to_v1(tmp_path: Path):
    enc_mgr, vault = setup(tmp_path)
    legacy = {"passwords": {"0": {"website": "a", "length": 8}}}
    enc_mgr.save_json_data(legacy)
    data = vault.load_index()
    assert data["schema_version"] == LATEST_VERSION
    assert data["passwords"] == legacy["passwords"]


def test_error_on_future_version(tmp_path: Path):
    enc_mgr, vault = setup(tmp_path)
    future = {"schema_version": LATEST_VERSION + 1, "passwords": {}}
    enc_mgr.save_json_data(future)
    with pytest.raises(ValueError):
        vault.load_index()
