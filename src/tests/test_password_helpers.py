import string
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


def test_derive_password_entropy_length():
    pg = make_generator()
    dk = pg._derive_password_entropy(index=1)
    assert isinstance(dk, bytes)
    assert len(dk) == 32
    dk2 = pg._derive_password_entropy(index=2)
    assert dk != dk2


def test_map_entropy_to_chars_only_uses_alphabet():
    pg = make_generator()
    alphabet = string.ascii_letters + string.digits
    mapped = pg._map_entropy_to_chars(b"\x00\x01\x02", alphabet)
    assert all(c in alphabet for c in mapped)
    assert len(mapped) == 3


def test_enforce_complexity_minimum_counts():
    pg = make_generator()
    alphabet = string.ascii_letters + string.digits + string.punctuation
    dk = bytes(range(32))
    result = pg._enforce_complexity("a" * 32, alphabet, string.punctuation, dk)
    assert sum(1 for c in result if c.isupper()) >= 2
    assert sum(1 for c in result if c.islower()) >= 2
    assert sum(1 for c in result if c.isdigit()) >= 2
    assert sum(1 for c in result if c in string.punctuation) >= 2


def test_shuffle_deterministically_repeatable():
    pg = make_generator()
    dk = bytes(range(32))
    pw1 = pg._shuffle_deterministically("abcdef", dk)
    pw2 = pg._shuffle_deterministically("abcdef", dk)
    assert pw1 == pw2
