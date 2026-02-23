import sys
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass.core.encryption import EncryptionManager


def make_manager(tmp_path):
    key = Fernet.generate_key()
    return EncryptionManager(key, tmp_path)


def test_validate_seed_valid_mnemonic(tmp_path):
    manager = make_manager(tmp_path)
    valid = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    is_valid, error = manager.validate_seed(valid)
    assert is_valid is True
    assert error is None


def test_validate_seed_invalid_mnemonic(tmp_path):
    manager = make_manager(tmp_path)
    invalid = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
    is_valid, error = manager.validate_seed(invalid)
    assert is_valid is False
    assert error == "Invalid seed phrase."
