import os
from pathlib import Path

from hypothesis import given, strategies as st, settings, HealthCheck
from mnemonic import Mnemonic

from utils.key_derivation import (
    derive_key_from_password,
    derive_key_from_password_argon2,
    derive_index_key,
)
from seedpass.core.encryption import EncryptionManager

cfg_values = st.one_of(
    st.integers(min_value=0, max_value=100),
    st.text(min_size=0, max_size=20),
    st.booleans(),
)


@given(
    password=st.text(min_size=8, max_size=32),
    seed_bytes=st.binary(min_size=16, max_size=16),
    config=st.dictionaries(st.text(min_size=1, max_size=10), cfg_values, max_size=5),
    mode=st.sampled_from(["pbkdf2", "argon2"]),
)
@settings(
    deadline=None,
    max_examples=20,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_fuzz_key_round_trip(password, seed_bytes, config, mode, tmp_path: Path):
    """Ensure EncryptionManager round-trips arbitrary data."""
    seed_phrase = Mnemonic("english").to_mnemonic(seed_bytes)
    if mode == "argon2":
        key = derive_key_from_password_argon2(
            password, time_cost=1, memory_cost=8, parallelism=1
        )
    else:
        key = derive_key_from_password(password, iterations=1)

    enc_mgr = EncryptionManager(key, tmp_path)

    # Parent seed round trip
    enc_mgr.encrypt_parent_seed(seed_phrase)
    assert enc_mgr.decrypt_parent_seed() == seed_phrase

    # JSON data round trip
    enc_mgr.save_json_data(config, Path("config.enc"))
    loaded = enc_mgr.load_json_data(Path("config.enc"))
    assert loaded == config

    # Binary data round trip
    blob = os.urandom(32)
    enc_mgr.encrypt_and_save_file(blob, Path("blob.enc"))
    assert enc_mgr.decrypt_file(Path("blob.enc")) == blob

    # Index key derived from seed also decrypts
    index_key = derive_index_key(seed_phrase)
    idx_mgr = EncryptionManager(index_key, tmp_path)
    idx_mgr.save_json_data(config)
    assert idx_mgr.load_json_data() == config
