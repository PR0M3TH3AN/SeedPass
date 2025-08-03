import string
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass.core.password_generation import PasswordGenerator, PasswordPolicy


class DummyEnc:
    def derive_seed_from_mnemonic(self, mnemonic):
        return b"\x00" * 32


class DummyBIP85:
    def derive_entropy(self, index: int, bytes_len: int, app_no: int = 32) -> bytes:
        return bytes((index + i) % 256 for i in range(bytes_len))


def make_generator(policy=None):
    pg = PasswordGenerator.__new__(PasswordGenerator)
    pg.encryption_manager = DummyEnc()
    pg.bip85 = DummyBIP85()
    pg.policy = policy or PasswordPolicy()
    return pg


def count_types(pw: str):
    return (
        sum(c.isupper() for c in pw),
        sum(c.islower() for c in pw),
        sum(c.isdigit() for c in pw),
        sum(c in string.punctuation for c in pw),
    )


def test_zero_policy_preserves_length():
    policy = PasswordPolicy(0, 0, 0, 0)
    pg = make_generator(policy)
    alphabet = string.ascii_lowercase
    dk = bytes(range(32))
    result = pg._enforce_complexity("a" * 32, alphabet, "", dk)
    assert len(result) == 32


def test_custom_policy_applied():
    policy = PasswordPolicy(
        min_uppercase=4, min_lowercase=1, min_digits=3, min_special=2
    )
    pg = make_generator(policy)
    alphabet = string.ascii_letters + string.digits + string.punctuation
    dk = bytes(range(32))
    result = pg._enforce_complexity("a" * 32, alphabet, string.punctuation, dk)
    counts = count_types(result)
    assert counts[0] >= 4
    assert counts[1] >= 1
    assert counts[2] >= 3
    assert counts[3] >= 2


def test_generate_password_respects_policy():
    policy = PasswordPolicy(
        min_uppercase=3, min_lowercase=3, min_digits=3, min_special=3
    )
    pg = make_generator(policy)
    pw = pg.generate_password(length=16, index=1)
    counts = count_types(pw)
    assert all(c >= 3 for c in counts)
