import pytest
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.password_generation import PasswordGenerator, PasswordPolicy
from constants import MIN_PASSWORD_LENGTH


class DummyEnc:
    def derive_seed_from_mnemonic(self, mnemonic):
        return b"\x00" * 32


class DummyBIP85:
    def derive_entropy(self, index: int, bytes_len: int, app_no: int = 32) -> bytes:
        return bytes((index + i) % 256 for i in range(bytes_len))


def make_generator():
    pg = PasswordGenerator.__new__(PasswordGenerator)
    pg.encryption_manager = DummyEnc()
    pg.bip85 = DummyBIP85()
    pg.policy = PasswordPolicy()
    return pg


def test_generate_password_too_short_raises():
    pg = make_generator()
    with pytest.raises(ValueError):
        pg.generate_password(length=MIN_PASSWORD_LENGTH - 1)
