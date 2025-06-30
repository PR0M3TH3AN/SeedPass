import logging
import pytest
from utils.key_derivation import derive_key_from_password


def test_derive_key_deterministic():
    password = "correct horse battery staple"
    key1 = derive_key_from_password(password, iterations=1)
    key2 = derive_key_from_password(password, iterations=1)
    assert key1 == key2
    assert len(key1) == 44
    logging.info("Deterministic key derivation succeeded")


def test_derive_key_empty_password_error():
    with pytest.raises(ValueError):
        derive_key_from_password("")
    logging.info("Empty password correctly raised ValueError")
