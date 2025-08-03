import logging
import pytest
from utils.fingerprint import generate_fingerprint
from utils.key_derivation import (
    derive_key_from_password,
    derive_key_from_password_argon2,
    derive_index_key_seed_only,
    derive_index_key,
)


def test_pbkdf2_fingerprint_affects_key():
    password = "correct horse battery staple"
    fp1 = generate_fingerprint("seed one")
    fp2 = generate_fingerprint("seed two")

    key1 = derive_key_from_password(password, fp1, iterations=1)
    key2 = derive_key_from_password(password, fp1, iterations=1)
    key3 = derive_key_from_password(password, fp2, iterations=1)

    assert key1 == key2
    assert key1 != key3
    assert len(key1) == 44
    logging.info("PBKDF2 fingerprint behaviour verified")


def test_derive_key_empty_password_error():
    with pytest.raises(ValueError):
        derive_key_from_password("", "fp")
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


def test_argon2_fingerprint_affects_key():
    password = "correct horse battery staple"
    fp1 = generate_fingerprint("seed one")
    fp2 = generate_fingerprint("seed two")

    k1 = derive_key_from_password_argon2(
        password, fp1, time_cost=1, memory_cost=8, parallelism=1
    )
    k2 = derive_key_from_password_argon2(
        password, fp1, time_cost=1, memory_cost=8, parallelism=1
    )
    k3 = derive_key_from_password_argon2(
        password, fp2, time_cost=1, memory_cost=8, parallelism=1
    )

    assert k1 == k2
    assert k1 != k3
    assert len(k1) == 44
