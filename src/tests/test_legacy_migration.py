import json
import hashlib
from pathlib import Path

from helpers import create_vault, TEST_SEED, TEST_PASSWORD
from utils.key_derivation import derive_index_key
from cryptography.fernet import Fernet


def test_legacy_index_migrates(tmp_path: Path):
    vault, _ = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)

    key = derive_index_key(TEST_SEED)
    data = {
        "schema_version": 4,
        "entries": {
            "0": {
                "label": "a",
                "length": 8,
                "type": "password",
                "kind": "password",
                "notes": "",
                "custom_fields": [],
                "origin": "",
                "tags": [],
            }
        },
    }
    enc = Fernet(key).encrypt(json.dumps(data).encode())
    legacy_file = tmp_path / "seedpass_passwords_db.json.enc"
    legacy_file.write_bytes(enc)
    (tmp_path / "seedpass_passwords_db_checksum.txt").write_text(
        hashlib.sha256(enc).hexdigest()
    )

    loaded = vault.load_index()
    assert loaded == data

    new_file = tmp_path / "seedpass_entries_db.json.enc"
    assert new_file.exists()
    assert not legacy_file.exists()
    assert not (tmp_path / "seedpass_passwords_db_checksum.txt").exists()
