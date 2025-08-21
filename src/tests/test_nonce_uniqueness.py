from pathlib import Path

from helpers import TEST_SEED
from utils.key_derivation import derive_index_key
from seedpass.core.encryption import EncryptionManager


def test_nonce_uniqueness(tmp_path: Path) -> None:
    key = derive_index_key(TEST_SEED)
    manager = EncryptionManager(key, tmp_path)
    plaintext = b"repeat"
    nonces = set()
    for _ in range(10):
        payload = manager.encrypt_data(plaintext)
        assert payload.startswith(b"V3|")
        nonce = payload[3:15]
        assert nonce not in nonces
        nonces.add(nonce)
    assert len(nonces) == 10
