import sys
import string
from pathlib import Path
from hypothesis import given, strategies as st, settings

sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass.core.password_generation import PasswordGenerator, PasswordPolicy
from seedpass.core.entry_types import EntryType


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


@given(
    length=st.integers(min_value=8, max_value=64),
    index=st.integers(min_value=0, max_value=1000),
)
@settings(deadline=None)
def test_password_properties(length, index):
    pg = make_generator()
    entry_type = EntryType.PASSWORD.value
    pw1 = pg.generate_password(length=length, index=index)
    pw2 = pg.generate_password(length=length, index=index)
    assert entry_type == "password"

    assert pw1 == pw2
    assert len(pw1) == length

    assert sum(c.isupper() for c in pw1) >= 2
    assert sum(c.islower() for c in pw1) >= 2
    assert sum(c.isdigit() for c in pw1) >= 2
    assert sum(c in string.punctuation for c in pw1) >= 2
    assert not any(c.isspace() for c in pw1)
