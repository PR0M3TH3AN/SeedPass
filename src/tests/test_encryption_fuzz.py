import pytest
from pathlib import Path
from cryptography.fernet import Fernet
from hypothesis import given, strategies as st, settings, HealthCheck

from seedpass.core.encryption import EncryptionManager


@given(blob=st.binary())
@settings(
    deadline=None,
    max_examples=25,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_encrypt_decrypt_roundtrip(blob: bytes, tmp_path: Path) -> None:
    """Ensure arbitrary data round-trips through EncryptionManager."""
    key = Fernet.generate_key()
    mgr = EncryptionManager(key, tmp_path)
    encrypted = mgr.encrypt_data(blob)
    assert mgr.decrypt_data(encrypted) == blob


@given(blob=st.binary())
@settings(
    deadline=None,
    max_examples=25,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_corrupted_ciphertext_fails(blob: bytes, tmp_path: Path) -> None:
    """Corrupted ciphertext should not decrypt successfully."""
    key = Fernet.generate_key()
    mgr = EncryptionManager(key, tmp_path)
    encrypted = bytearray(mgr.encrypt_data(blob))
    if encrypted:
        encrypted[0] ^= 0xFF
    with pytest.raises(Exception):
        mgr.decrypt_data(bytes(encrypted))
