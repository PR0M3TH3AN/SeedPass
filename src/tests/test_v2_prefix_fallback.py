import logging
import os
from pathlib import Path

import pytest
from cryptography.fernet import InvalidToken

from helpers import TEST_SEED
from utils.key_derivation import derive_index_key
from password_manager.encryption import EncryptionManager


def test_v2_prefix_fernet_fallback(tmp_path: Path, caplog) -> None:
    key = derive_index_key(TEST_SEED)
    manager = EncryptionManager(key, tmp_path)

    original = b"legacy data"
    token = manager.fernet.encrypt(original)
    payload = b"V2:" + token

    caplog.set_level(logging.WARNING, logger="password_manager.encryption")
    decrypted = manager.decrypt_data(payload)

    assert decrypted == original
    assert "incorrect 'V2:' header" in caplog.text


def test_aesgcm_payload_too_short(tmp_path: Path, caplog) -> None:
    key = derive_index_key(TEST_SEED)
    manager = EncryptionManager(key, tmp_path)

    payload = b"V2:" + os.urandom(12) + b"short"

    caplog.set_level(logging.ERROR, logger="password_manager.encryption")
    with pytest.raises(InvalidToken, match="AES-GCM payload too short"):
        manager.decrypt_data(payload)

    assert "AES-GCM payload too short" in caplog.text
