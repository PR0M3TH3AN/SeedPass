import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

import pytest

from utils.memory_protection import InMemorySecret


def test_inmemory_secret_round_trip_bytes_and_str():
    plaintext = b"super secret"
    secret = InMemorySecret(plaintext)
    assert secret.get_bytes() == plaintext
    assert secret.get_str() == plaintext.decode("utf-8")


def test_inmemory_secret_invalid_type():
    with pytest.raises(TypeError):
        InMemorySecret("not bytes")


def test_inmemory_secret_wipe_clears_attributes():
    secret = InMemorySecret(b"wipe me")
    secret.wipe()
    assert secret._key is None
    assert secret._nonce is None
    assert secret._cipher is None
    assert secret._encrypted is None
