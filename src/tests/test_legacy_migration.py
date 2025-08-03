import json
import hashlib
from pathlib import Path

from helpers import create_vault, TEST_SEED, TEST_PASSWORD
from utils.key_derivation import derive_index_key
from cryptography.fernet import Fernet
from types import SimpleNamespace

from seedpass.core.manager import PasswordManager, EncryptionMode
from seedpass.core.vault import Vault


def test_legacy_index_migrates(monkeypatch, tmp_path: Path):
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

    monkeypatch.setattr("builtins.input", lambda *_a, **_k: "y")

    loaded = vault.load_index()
    assert loaded == data

    new_file = tmp_path / "seedpass_entries_db.json.enc"
    assert new_file.exists()
    assert not legacy_file.exists()
    assert not (tmp_path / "seedpass_passwords_db_checksum.txt").exists()
    backup = tmp_path / "legacy_backups" / "seedpass_passwords_db.json.enc"
    assert backup.exists()


def test_migration_triggers_sync(monkeypatch, tmp_path: Path):
    vault, enc_mgr = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)

    key = derive_index_key(TEST_SEED)
    data = {"schema_version": 4, "entries": {}}
    enc = Fernet(key).encrypt(json.dumps(data).encode())
    legacy_file = tmp_path / "seedpass_passwords_db.json.enc"
    legacy_file.write_bytes(enc)

    monkeypatch.setattr("builtins.input", lambda *_a, **_k: "y")

    pm = PasswordManager.__new__(PasswordManager)
    pm.encryption_mode = EncryptionMode.SEED_ONLY
    pm.encryption_manager = enc_mgr
    pm.vault = Vault(enc_mgr, tmp_path)
    pm.parent_seed = TEST_SEED
    pm.fingerprint_dir = tmp_path
    pm.current_fingerprint = tmp_path.name
    pm.bip85 = SimpleNamespace()

    calls = {"sync": 0}
    pm.start_background_vault_sync = lambda *a, **k: calls.__setitem__(
        "sync", calls["sync"] + 1
    )

    monkeypatch.setattr(
        "seedpass.core.manager.NostrClient", lambda *a, **k: SimpleNamespace()
    )

    pm.initialize_managers()
    assert calls["sync"] == 1
