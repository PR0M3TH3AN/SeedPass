import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass.core.password_generation import PasswordGenerator, PasswordPolicy


class DummyEnc:
    def derive_seed_from_mnemonic(self, mnemonic):
        return b"\x00" * 32


class DummyBIP85:
    def derive_entropy(self, index: int, entropy_bytes: int, app_no: int = 32) -> bytes:
        return bytes((index + i) % 256 for i in range(entropy_bytes))


def make_generator():
    pg = PasswordGenerator.__new__(PasswordGenerator)
    pg.encryption_manager = DummyEnc()
    pg.bip85 = DummyBIP85()
    pg.policy = PasswordPolicy()
    return pg


def test_password_generation_consistent_output():
    pg = make_generator()
    expected = "0j6R3e-%4xN@N{Jb"
    assert pg.generate_password(length=16, index=1) == expected
    # Generating again should produce the same password
    assert pg.generate_password(length=16, index=1) == expected
