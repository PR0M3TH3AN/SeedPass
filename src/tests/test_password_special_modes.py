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
    def derive_entropy(self, index: int, entropy_bytes: int, app_no: int = 32) -> bytes:
        return bytes((index + i) % 256 for i in range(entropy_bytes))


def make_generator(policy=None):
    pg = PasswordGenerator.__new__(PasswordGenerator)
    pg.encryption_manager = DummyEnc()
    pg.bip85 = DummyBIP85()
    pg.policy = policy or PasswordPolicy()
    return pg


def test_include_special_chars_false():
    policy = PasswordPolicy(include_special_chars=False)
    pg = make_generator(policy)
    pw = pg.generate_password(length=32, index=0)
    assert not any(c in string.punctuation for c in pw)


def test_safe_mode_uses_safe_chars():
    policy = PasswordPolicy(special_mode="safe")
    pg = make_generator(policy)
    pw = pg.generate_password(length=32, index=1)
    specials = [c for c in pw if c in string.punctuation]
    assert specials and all(c in SAFE_SPECIAL_CHARS for c in specials)


def test_allowed_chars_override_special_mode():
    allowed = "@#$"
    policy = PasswordPolicy(special_mode="safe", allowed_special_chars=allowed)
    pg = make_generator(policy)
    pw = pg.generate_password(length=32, index=2)
    specials = [c for c in pw if c in string.punctuation]
    assert specials and all(c in allowed for c in specials)


def test_enforce_complexity_min_special_zero():
    policy = PasswordPolicy(min_special=0)
    pg = make_generator(policy)
    alphabet = string.ascii_letters + string.digits + string.punctuation
    dk = bytes(range(32))
    result = pg._enforce_complexity("a" * 32, alphabet, string.punctuation, dk)
    assert len(result) == 32
    assert sum(c.isupper() for c in result) >= 2
    assert sum(c.islower() for c in result) >= 2
    assert sum(c.isdigit() for c in result) >= 2
