import json
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from seedpass.core.encryption import (
    EncryptionManager,
    LegacyFormatRequiresMigrationError,
    _derive_legacy_key_from_password,
)
from seedpass.core.vault import Vault


def test_decrypt_data_raises_legacy_exception(tmp_path: Path) -> None:
    key = Fernet.generate_key()
    mgr = EncryptionManager(key, tmp_path)
    with pytest.raises(LegacyFormatRequiresMigrationError):
        mgr.decrypt_data(b"not a valid token")


def test_vault_handles_legacy_exception(tmp_path: Path, monkeypatch) -> None:
    password = "secret"
    legacy_key = _derive_legacy_key_from_password(password)
    legacy_mgr = EncryptionManager(legacy_key, tmp_path)
    payload = json.dumps(
        {"schema_version": 3, "entries": {"1": {"kind": "password", "password": "x"}}}
    ).encode("utf-8")
    legacy_bytes = legacy_mgr.fernet.encrypt(payload)
    index_file = tmp_path / Vault.INDEX_FILENAME
    index_file.write_bytes(legacy_bytes)

    new_mgr = EncryptionManager(Fernet.generate_key(), tmp_path)
    vault = Vault(new_mgr, tmp_path)

    monkeypatch.setattr("builtins.input", lambda *args, **kwargs: "1")
    monkeypatch.setattr(
        "seedpass.core.vault.prompt_existing_password", lambda *args, **kwargs: password
    )

    data, migrated, last = vault.load_index(return_migration_flags=True)
    assert "1" in data["entries"]
    assert last is False
