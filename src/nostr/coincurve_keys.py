from __future__ import annotations

from bech32 import bech32_encode, bech32_decode, convertbits
from coincurve import PrivateKey, PublicKey


class Keys:
    """Minimal replacement for monstr.encrypt.Keys using coincurve."""

    def __init__(self, priv_k: str | None = None, pub_k: str | None = None):
        if priv_k is not None:
            if priv_k.startswith("nsec"):
                priv_k = self.bech32_to_hex(priv_k)
            self._priv_k = priv_k
            priv = PrivateKey(bytes.fromhex(priv_k))
        else:
            priv = PrivateKey()
            self._priv_k = priv.to_hex()

        pub = priv.public_key.format(compressed=True).hex()[2:]
        if pub_k:
            if pub_k.startswith("npub"):
                pub_k = self.bech32_to_hex(pub_k)
            self._pub_k = pub_k
        else:
            self._pub_k = pub

    @staticmethod
    def hex_to_bech32(key_str: str, prefix: str = "npub") -> str:
        data = convertbits(bytes.fromhex(key_str), 8, 5)
        return bech32_encode(prefix, data)

    @staticmethod
    def bech32_to_hex(key: str) -> str:
        hrp, data = bech32_decode(key)
        if data is None:
            raise ValueError("Invalid bech32 key")
        decoded = convertbits(data, 5, 8, False)
        return bytes(decoded).hex()

    def private_key_hex(self) -> str:
        return self._priv_k

    def public_key_hex(self) -> str:
        return self._pub_k
