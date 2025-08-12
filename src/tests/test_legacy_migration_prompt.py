import base64
import json
from pathlib import Path

from seedpass.core.encryption import (
    EncryptionManager,
    _derive_legacy_key_from_password,
)
from seedpass.core.vault import Vault
import seedpass.core.vault as vault_module
from seedpass.core.migrations import LATEST_VERSION


def _setup_legacy_file(tmp_path: Path, password: str) -> Path:
    legacy_key = _derive_legacy_key_from_password(password, iterations=50_000)
    legacy_mgr = EncryptionManager(legacy_key, tmp_path)
    data = {"schema_version": LATEST_VERSION, "entries": {"0": {"kind": "test"}}}
    json_bytes = json.dumps(data, separators=(",", ":")).encode("utf-8")
    legacy_encrypted = legacy_mgr.fernet.encrypt(json_bytes)
    file_path = tmp_path / "seedpass_entries_db.json.enc"
    file_path.write_bytes(legacy_encrypted)
    return file_path


def test_open_legacy_without_migrating(tmp_path, monkeypatch):
    password = "secret"
    _setup_legacy_file(tmp_path, password)
    new_key = base64.urlsafe_b64encode(b"A" * 32)
    mgr = EncryptionManager(new_key, tmp_path)
    vault = Vault(mgr, tmp_path)
    monkeypatch.setattr(
        "seedpass.core.encryption.prompt_existing_password", lambda _: password
    )
    monkeypatch.setattr(vault_module, "prompt_existing_password", lambda _: password)
    monkeypatch.setattr("builtins.input", lambda _: "1")
    vault.load_index()
    assert vault.encryption_manager.last_migration_performed is False
    assert vault.migrated_from_legacy is False


def test_migrate_legacy_sets_flag(tmp_path, monkeypatch):
    password = "secret"
    _setup_legacy_file(tmp_path, password)
    new_key = base64.urlsafe_b64encode(b"B" * 32)
    mgr = EncryptionManager(new_key, tmp_path)
    vault = Vault(mgr, tmp_path)
    monkeypatch.setattr(
        "seedpass.core.encryption.prompt_existing_password", lambda _: password
    )
    monkeypatch.setattr(vault_module, "prompt_existing_password", lambda _: password)
    monkeypatch.setattr("builtins.input", lambda _: "2")
    vault.load_index()
    content = (tmp_path / "seedpass_entries_db.json.enc").read_bytes()
    assert content.startswith(b"V2:")
    assert vault.encryption_manager.last_migration_performed is True
