import base64
import hashlib
import unicodedata

import pytest
from cryptography.fernet import InvalidToken

from helpers import TEST_PASSWORD, TEST_SEED
from seedpass.core.encryption import EncryptionManager
from utils.key_derivation import derive_index_key


def test_wrong_password_message(tmp_path):
    key = derive_index_key(TEST_SEED)
    mgr = EncryptionManager(key, tmp_path)
    payload = mgr.encrypt_data(b"secret")

    wrong_key = bytearray(key)
    wrong_key[0] ^= 1
    wrong_mgr = EncryptionManager(bytes(wrong_key), tmp_path)

    with pytest.raises(InvalidToken, match="invalid key or corrupt file") as exc:
        wrong_mgr.decrypt_data(payload, context="index")
    assert "index" in str(exc.value)


def test_legacy_file_requires_migration_message(tmp_path, monkeypatch, capsys):
    def _fast_legacy_key(password: str, iterations: int = 100_000) -> bytes:
        normalized = unicodedata.normalize("NFKD", password).strip().encode("utf-8")
        key = hashlib.pbkdf2_hmac("sha256", normalized, b"", 1, dklen=32)
        return base64.urlsafe_b64encode(key)

    monkeypatch.setattr(
        "seedpass.core.encryption._derive_legacy_key_from_password", _fast_legacy_key
    )
    monkeypatch.setattr(
        "seedpass.core.encryption.prompt_existing_password",
        lambda *_a, **_k: TEST_PASSWORD,
    )
    monkeypatch.setattr("builtins.input", lambda *_a, **_k: "1")

    legacy_key = _fast_legacy_key(TEST_PASSWORD)
    legacy_mgr = EncryptionManager(legacy_key, tmp_path)
    token = legacy_mgr.fernet.encrypt(b"secret")

    new_mgr = EncryptionManager(derive_index_key(TEST_SEED), tmp_path)
    assert new_mgr.decrypt_data(token, context="index") == b"secret"

    out = capsys.readouterr().out
    assert "Failed to decrypt index" in out
    assert "legacy index" in out


def test_corrupted_data_message(tmp_path):
    key = derive_index_key(TEST_SEED)
    mgr = EncryptionManager(key, tmp_path)
    payload = bytearray(mgr.encrypt_data(b"secret"))
    payload[-1] ^= 0xFF

    with pytest.raises(InvalidToken, match="invalid key or corrupt file") as exc:
        mgr.decrypt_data(bytes(payload), context="index")
    assert "index" in str(exc.value)
