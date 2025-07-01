import logging
import pytest
from utils.key_derivation import (
    derive_key_from_password,
    derive_index_key_seed_only,
    derive_index_key_seed_plus_pw,
)


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


def test_seed_only_key_deterministic():
    seed = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    k1 = derive_index_key_seed_only(seed)
    k2 = derive_index_key_seed_only(seed)
    assert k1 == k2
    assert len(k1) == 44


def test_seed_plus_pw_differs_from_seed_only():
    seed = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    pw = "hunter2"
    k1 = derive_index_key_seed_only(seed)
    k2 = derive_index_key_seed_plus_pw(seed, pw)
    assert k1 != k2
