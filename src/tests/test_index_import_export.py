from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
import sys
from helpers import create_vault, TEST_SEED, TEST_PASSWORD
from utils.fingerprint import generate_fingerprint

sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass.core.encryption import EncryptionManager
from seedpass.core.vault import Vault
from utils.key_derivation import derive_index_key, derive_key_from_password

SEED = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
PASSWORD = "passw0rd"


def setup_vault(tmp: Path) -> Vault:
    fp = generate_fingerprint(SEED)
    seed_key = derive_key_from_password(PASSWORD, fp)
    seed_mgr = EncryptionManager(seed_key, tmp)
    seed_mgr.encrypt_parent_seed(SEED)

    key = derive_index_key(SEED)
    enc_mgr = EncryptionManager(key, tmp)
    return Vault(enc_mgr, tmp)


def test_index_export_import_round_trip():
    with TemporaryDirectory() as td:
        tmp = Path(td)
        vault = setup_vault(tmp)

        original = {
            "schema_version": 4,
            "entries": {
                "0": {
                    "label": "example",
                    "type": "password",
                    "notes": "",
                    "custom_fields": [],
                    "origin": "",
                    "tags": [],
                }
            },
        }
        vault.save_index(original)

        encrypted = vault.get_encrypted_index()
        assert isinstance(encrypted, bytes)

        vault.save_index(
            {
                "schema_version": 4,
                "entries": {
                    "0": {
                        "label": "changed",
                        "type": "password",
                        "notes": "",
                        "custom_fields": [],
                        "origin": "",
                        "tags": [],
                    }
                },
            }
        )
        assert vault.decrypt_and_save_index_from_nostr(encrypted)

        loaded = vault.load_index()
        assert loaded["entries"] == original["entries"]


def test_get_encrypted_index_missing_file(tmp_path):
    vault, enc_mgr = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    assert vault.get_encrypted_index() is None
