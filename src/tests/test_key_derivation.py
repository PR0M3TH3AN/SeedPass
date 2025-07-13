import logging
import pytest
from utils.key_derivation import (
    derive_key_from_password,
    derive_key_from_password_argon2,
    derive_index_key_seed_only,
    derive_index_key,
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


def test_derive_index_key_seed_only():
    seed = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    assert derive_index_key(seed) == derive_index_key_seed_only(seed)


def test_argon2_key_deterministic():
    pw = "correct horse battery staple"
    k1 = derive_key_from_password_argon2(pw, time_cost=1, memory_cost=8, parallelism=1)
    k2 = derive_key_from_password_argon2(pw, time_cost=1, memory_cost=8, parallelism=1)
    assert k1 == k2
    assert len(k1) == 44
