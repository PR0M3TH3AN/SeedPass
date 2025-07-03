import pytest
from bech32 import bech32_encode, convertbits

from nostr.key_manager import KeyManager


def test_key_manager_getters(monkeypatch):
    priv_hex = "1" * 64
    pub_hex = "2" * 64

    class DummyKeys:
        def public_key_hex(self):
            return pub_hex

        def private_key_hex(self):
            return priv_hex

    monkeypatch.setattr(KeyManager, "initialize_bip85", lambda self: None)
    monkeypatch.setattr(KeyManager, "generate_nostr_keys", lambda self: DummyKeys())

    km = KeyManager("seed", "fp")

    assert km.get_public_key_hex() == pub_hex
    assert km.get_private_key_hex() == priv_hex

    expected_npub = bech32_encode(
        "npub", convertbits(bytes.fromhex(pub_hex), 8, 5, True)
    )
    assert km.get_npub() == expected_npub
