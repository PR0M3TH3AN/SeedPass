import json
import base64
import hashlib
from pathlib import Path

import pytest

from helpers import create_vault, TEST_SEED, TEST_PASSWORD
from utils.key_derivation import derive_index_key
from cryptography.fernet import Fernet
from types import SimpleNamespace
import asyncio
import gzip

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


def test_failed_migration_restores_legacy(monkeypatch, tmp_path: Path):
    vault, enc_mgr = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)

    key = derive_index_key(TEST_SEED)
    data = {"schema_version": 4, "entries": {}}
    enc = Fernet(key).encrypt(json.dumps(data).encode())
    legacy_file = tmp_path / "seedpass_passwords_db.json.enc"
    legacy_file.write_bytes(enc)
    checksum = hashlib.sha256(enc).hexdigest()
    (tmp_path / "seedpass_passwords_db_checksum.txt").write_text(checksum)

    monkeypatch.setattr("builtins.input", lambda *_a, **_k: "y")

    def bad_load_json(_path):
        raise ValueError("boom")

    monkeypatch.setattr(enc_mgr, "load_json_data", bad_load_json)

    with pytest.raises(RuntimeError, match="Migration failed:"):
        vault.load_index()

    # Legacy file restored and new index removed
    assert legacy_file.exists()
    assert not (tmp_path / "seedpass_entries_db.json.enc").exists()
    assert (tmp_path / "seedpass_passwords_db_checksum.txt").read_text() == checksum
    assert not vault.migrated_from_legacy


def test_migrated_index_has_v3_prefix(monkeypatch, tmp_path: Path):
    vault, _ = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)

    key = derive_index_key(TEST_SEED)
    data = {"schema_version": 4, "entries": {}}
    enc = Fernet(key).encrypt(json.dumps(data).encode())
    legacy_file = tmp_path / "seedpass_passwords_db.json.enc"
    legacy_file.write_bytes(enc)
    (tmp_path / "seedpass_passwords_db_checksum.txt").write_text(
        hashlib.sha256(enc).hexdigest()
    )

    monkeypatch.setattr("builtins.input", lambda *_a, **_k: "y")

    vault.load_index()

    new_file = tmp_path / "seedpass_entries_db.json.enc"
    payload = json.loads(new_file.read_text())
    assert base64.b64decode(payload["ct"]).startswith(b"V3|")
    assert vault.migrated_from_legacy


def test_legacy_index_migration_removes_strays(monkeypatch, tmp_path: Path):
    vault, _ = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)

    key = derive_index_key(TEST_SEED)
    data = {"schema_version": 4, "entries": {}}
    enc = Fernet(key).encrypt(json.dumps(data).encode())

    legacy_file = tmp_path / "seedpass_passwords_db.json.enc"
    legacy_file.write_bytes(enc)
    (tmp_path / "seedpass_passwords_db_checksum.txt").write_text(
        hashlib.sha256(enc).hexdigest()
    )

    stray_file = tmp_path / "seedpass_passwords_db.extra.enc"
    stray_file.write_text("junk")

    monkeypatch.setattr("builtins.input", lambda *_a, **_k: "y")

    # First load triggers migration and removes stray legacy files
    loaded = vault.load_index()
    assert loaded == data
    assert not stray_file.exists()

    # Subsequent load should not detect any legacy files
    loaded_again = vault.load_index()
    assert loaded_again == data

    assert (tmp_path / "seedpass_entries_db.json.enc").exists()
    assert list(tmp_path.glob("seedpass_passwords_db*.enc")) == []
    assert not (tmp_path / "seedpass_passwords_db_checksum.txt").exists()


def test_migration_syncs_when_confirmed(monkeypatch, tmp_path: Path):
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
    from seedpass.core.config_manager import ConfigManager

    cfg_mgr = ConfigManager(pm.vault, tmp_path)
    cfg = cfg_mgr.load_config(require_pin=False)
    cfg["offline_mode"] = False
    cfg_mgr.save_config(cfg)
    pm.config_manager = cfg_mgr
    pm.offline_mode = False

    calls = {"sync": 0}
    pm.sync_vault = lambda *a, **k: calls.__setitem__("sync", calls["sync"] + 1) or {
        "manifest_id": "m",
        "chunk_ids": [],
        "delta_ids": [],
    }

    monkeypatch.setattr(
        "seedpass.core.manager.NostrClient", lambda *a, **k: SimpleNamespace()
    )
    monkeypatch.setattr("seedpass.core.manager.confirm_action", lambda *_a, **_k: True)

    pm.initialize_managers()
    assert calls["sync"] == 1
    assert enc_mgr.last_migration_performed is False


def test_migration_declines_sync(monkeypatch, tmp_path: Path):
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
    pm.sync_vault = lambda *a, **k: calls.__setitem__("sync", calls["sync"] + 1) or {
        "manifest_id": "m",
        "chunk_ids": [],
        "delta_ids": [],
    }

    monkeypatch.setattr(
        "seedpass.core.manager.NostrClient", lambda *a, **k: SimpleNamespace()
    )
    monkeypatch.setattr("seedpass.core.manager.confirm_action", lambda *_a, **_k: False)

    pm.initialize_managers()
    assert calls["sync"] == 0
    assert enc_mgr.last_migration_performed is False


def test_legacy_nostr_payload_syncs_when_confirmed(monkeypatch, tmp_path: Path):
    vault, enc_mgr = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)

    key = derive_index_key(TEST_SEED)
    data = {"schema_version": 4, "entries": {}}
    legacy_enc = Fernet(key).encrypt(json.dumps(data).encode())
    compressed = gzip.compress(legacy_enc)

    class DummyClient:
        def __init__(self):
            self.relays = []
            self.last_error = None
            self.fingerprint = None

        async def fetch_latest_snapshot(self):
            from nostr.backup_models import Manifest

            return Manifest(ver=1, algo="gzip", chunks=[], delta_since=None), [
                compressed
            ]

        async def fetch_deltas_since(self, version):
            return []

    pm = PasswordManager.__new__(PasswordManager)
    pm.encryption_mode = EncryptionMode.SEED_ONLY
    pm.encryption_manager = enc_mgr
    pm.vault = Vault(enc_mgr, tmp_path)
    pm.parent_seed = TEST_SEED
    pm.fingerprint_dir = tmp_path
    pm.current_fingerprint = tmp_path.name
    pm.nostr_client = DummyClient()
    pm.offline_mode = False

    calls = {"sync": 0}

    async def fake_sync_vault_async(*_a, **_k):
        calls["sync"] += 1
        return True

    pm.sync_vault_async = fake_sync_vault_async
    monkeypatch.setattr("seedpass.core.manager.confirm_action", lambda *_a, **_k: True)

    asyncio.run(pm.sync_index_from_nostr_async())
    assert calls["sync"] == 1
    assert pm.vault.load_index() == data
    assert enc_mgr.last_migration_performed is False


def test_legacy_index_reinit_syncs_once_when_confirmed(monkeypatch, tmp_path: Path):
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
    pm.offline_mode = True

    monkeypatch.setattr(
        "seedpass.core.manager.NostrClient", lambda *a, **k: SimpleNamespace()
    )

    calls = {"sync": 0}
    pm.sync_vault = lambda *a, **k: calls.__setitem__("sync", calls["sync"] + 1) or {
        "manifest_id": "m",
        "chunk_ids": [],
        "delta_ids": [],
    }

    monkeypatch.setattr("seedpass.core.manager.confirm_action", lambda *_a, **_k: True)

    pm.initialize_managers()
    pm.initialize_managers()

    assert calls["sync"] == 0
    assert enc_mgr.last_migration_performed is False


def test_schema_migration_no_sync_prompt(monkeypatch, tmp_path: Path):
    vault, enc_mgr = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)

    data = {"schema_version": 3, "entries": {}}
    enc_mgr.save_json_data(data, Path("seedpass_entries_db.json.enc"))
    enc_mgr.update_checksum(Path("seedpass_entries_db.json.enc"))
    assert enc_mgr.last_migration_performed is False

    pm = PasswordManager.__new__(PasswordManager)
    pm.encryption_mode = EncryptionMode.SEED_ONLY
    pm.encryption_manager = enc_mgr
    pm.vault = Vault(enc_mgr, tmp_path)
    pm.parent_seed = TEST_SEED
    pm.fingerprint_dir = tmp_path
    pm.current_fingerprint = tmp_path.name
    pm.bip85 = SimpleNamespace()
    from seedpass.core.config_manager import ConfigManager

    cfg_mgr = ConfigManager(pm.vault, tmp_path)
    cfg = cfg_mgr.load_config(require_pin=False)
    cfg["offline_mode"] = False
    cfg_mgr.save_config(cfg)
    pm.config_manager = cfg_mgr
    pm.offline_mode = False

    calls = {"sync": 0, "confirm": 0}

    pm.sync_vault = lambda *a, **k: calls.__setitem__("sync", calls["sync"] + 1) or {
        "manifest_id": "m",
        "chunk_ids": [],
        "delta_ids": [],
    }

    monkeypatch.setattr(
        "seedpass.core.manager.NostrClient", lambda *a, **k: SimpleNamespace()
    )

    def fake_confirm(*_a, **_k):
        calls["confirm"] += 1
        return True

    monkeypatch.setattr("seedpass.core.manager.confirm_action", fake_confirm)

    pm.initialize_managers()
    assert calls["sync"] == 0
    assert calls["confirm"] == 0
    assert enc_mgr.last_migration_performed is False


def test_declined_migration_no_sync_prompt(monkeypatch, tmp_path: Path):
    vault, enc_mgr = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)

    key = derive_index_key(TEST_SEED)
    data = {"schema_version": 4, "entries": {}}
    enc = Fernet(key).encrypt(json.dumps(data).encode())
    legacy_file = tmp_path / "seedpass_passwords_db.json.enc"
    legacy_file.write_bytes(enc)

    monkeypatch.setattr("builtins.input", lambda *_a, **_k: "n")

    pm = PasswordManager.__new__(PasswordManager)
    pm.encryption_mode = EncryptionMode.SEED_ONLY
    pm.encryption_manager = enc_mgr
    pm.vault = Vault(enc_mgr, tmp_path)
    pm.parent_seed = TEST_SEED
    pm.fingerprint_dir = tmp_path
    pm.current_fingerprint = tmp_path.name
    pm.bip85 = SimpleNamespace()

    calls = {"confirm": 0}

    def fake_confirm(*_a, **_k):
        calls["confirm"] += 1
        return True

    monkeypatch.setattr("seedpass.core.manager.confirm_action", fake_confirm)

    with pytest.raises(SystemExit):
        pm.initialize_managers()

    assert calls["confirm"] == 0


def test_failed_migration_no_sync_prompt(monkeypatch, tmp_path: Path):
    vault, enc_mgr = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)

    key = derive_index_key(TEST_SEED)
    data = {"schema_version": 4, "entries": {}}
    enc = Fernet(key).encrypt(json.dumps(data).encode())
    legacy_file = tmp_path / "seedpass_passwords_db.json.enc"
    legacy_file.write_bytes(enc)

    monkeypatch.setattr("builtins.input", lambda *_a, **_k: "y")

    def fail(*_a, **_k):
        raise ValueError("boom")

    monkeypatch.setattr(enc_mgr, "load_json_data", fail)

    pm = PasswordManager.__new__(PasswordManager)
    pm.encryption_mode = EncryptionMode.SEED_ONLY
    pm.encryption_manager = enc_mgr
    pm.vault = Vault(enc_mgr, tmp_path)
    pm.parent_seed = TEST_SEED
    pm.fingerprint_dir = tmp_path
    pm.current_fingerprint = tmp_path.name
    pm.bip85 = SimpleNamespace()

    calls = {"confirm": 0}

    def fake_confirm(*_a, **_k):
        calls["confirm"] += 1
        return True

    monkeypatch.setattr("seedpass.core.manager.confirm_action", fake_confirm)

    with pytest.raises(SystemExit):
        pm.initialize_managers()

    assert calls["confirm"] == 0
