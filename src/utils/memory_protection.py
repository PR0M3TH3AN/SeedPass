from __future__ import annotations

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# TODO: Replace this Python implementation with a Rust/WASM module for
# critical cryptographic operations.


class InMemorySecret:
    """Store sensitive data encrypted in RAM using AES-GCM.

    Zeroization is best-effort only; Python's memory management may retain
    copies of the plaintext.
    """

    def __init__(self, data: bytes) -> None:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be bytes")
        self._key = AESGCM.generate_key(bit_length=128)
        self._nonce = os.urandom(12)
        self._cipher = AESGCM(self._key)
        self._encrypted = self._cipher.encrypt(self._nonce, bytes(data), None)

    def get_bytes(self) -> bytes:
        """Decrypt and return the plaintext bytes."""
        return self._cipher.decrypt(self._nonce, self._encrypted, None)

    def wipe(self) -> None:
        """Zero out internal data."""
        self._key = None
        self._nonce = None
        self._cipher = None
        self._encrypted = None

    def get_str(self) -> str:
        """Return the decrypted plaintext as a UTF-8 string."""
        return self.get_bytes().decode("utf-8")
