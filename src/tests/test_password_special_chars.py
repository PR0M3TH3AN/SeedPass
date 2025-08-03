import string
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from constants import SAFE_SPECIAL_CHARS

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


def test_no_special_chars():
    policy = PasswordPolicy(include_special_chars=False)
    pg = make_generator(policy)
    pw = pg.generate_password(length=16, index=0)
    assert not any(c in string.punctuation for c in pw)


def test_allowed_special_chars_only():
    allowed = "@$"
    policy = PasswordPolicy(allowed_special_chars=allowed)
    pg = make_generator(policy)
    pw = pg.generate_password(length=32, index=1)
    specials = [c for c in pw if c in string.punctuation]
    assert specials and all(c in allowed for c in specials)


def test_exclude_ambiguous_chars():
    policy = PasswordPolicy(exclude_ambiguous=True)
    pg = make_generator(policy)
    pw = pg.generate_password(length=32, index=2)
    for ch in "O0Il1":
        assert ch not in pw


def test_safe_special_chars_mode():
    policy = PasswordPolicy(special_mode="safe")
    pg = make_generator(policy)
    pw = pg.generate_password(length=32, index=3)
    specials = [c for c in pw if c in string.punctuation]
    assert specials and all(c in SAFE_SPECIAL_CHARS for c in specials)
