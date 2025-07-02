from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
import sys
from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.encryption import EncryptionManager
from password_manager.vault import Vault
from utils.key_derivation import (
    derive_index_key,
    derive_key_from_password,
    EncryptionMode,
)

SEED = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
PASSWORD = "passw0rd"


def setup_vault(tmp: Path, mode: EncryptionMode) -> Vault:
    seed_key = derive_key_from_password(PASSWORD)
    seed_mgr = EncryptionManager(seed_key, tmp)
    seed_mgr.encrypt_parent_seed(SEED)

    key = derive_index_key(SEED, PASSWORD, mode)
    enc_mgr = EncryptionManager(key, tmp)
    return Vault(enc_mgr, tmp)


@pytest.mark.parametrize(
    "mode",
    [
        EncryptionMode.SEED_ONLY,
        EncryptionMode.SEED_PLUS_PW,
        EncryptionMode.PW_ONLY,
    ],
)
def test_index_export_import_round_trip(mode):
    with TemporaryDirectory() as td:
        tmp = Path(td)
        vault = setup_vault(tmp, mode)

        original = {"passwords": {"0": {"website": "example"}}}
        vault.save_index(original)

        encrypted = vault.get_encrypted_index()
        assert isinstance(encrypted, bytes)

        vault.save_index({"passwords": {"0": {"website": "changed"}}})
        vault.decrypt_and_save_index_from_nostr(encrypted)

        loaded = vault.load_index()
        assert loaded["passwords"] == original["passwords"]


def test_get_encrypted_index_missing_file(tmp_path):
    vault, enc_mgr = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    assert vault.get_encrypted_index() is None
