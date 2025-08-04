import base64
import json
from pathlib import Path

from seedpass.core.encryption import (
    EncryptionManager,
    _derive_legacy_key_from_password,
)


def _setup_legacy_file(tmp_path: Path, password: str) -> Path:
    legacy_key = _derive_legacy_key_from_password(password, iterations=50_000)
    legacy_mgr = EncryptionManager(legacy_key, tmp_path)
    data = {"entries": {"0": {"kind": "test"}}}
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
    monkeypatch.setattr(
        "seedpass.core.encryption.prompt_existing_password", lambda _: password
    )
    monkeypatch.setattr("builtins.input", lambda _: "1")
    mgr.load_json_data()
    content = (tmp_path / "seedpass_entries_db.json.enc").read_bytes()
    assert not content.startswith(b"V2:")
    assert mgr.last_migration_performed is False


def test_migrate_legacy_sets_flag(tmp_path, monkeypatch):
    password = "secret"
    _setup_legacy_file(tmp_path, password)
    new_key = base64.urlsafe_b64encode(b"B" * 32)
    mgr = EncryptionManager(new_key, tmp_path)
    monkeypatch.setattr(
        "seedpass.core.encryption.prompt_existing_password", lambda _: password
    )
    monkeypatch.setattr("builtins.input", lambda _: "2")
    mgr.load_json_data()
    content = (tmp_path / "seedpass_entries_db.json.enc").read_bytes()
    assert content.startswith(b"V2:")
    assert mgr.last_migration_performed is True
