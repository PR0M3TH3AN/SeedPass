from __future__ import annotations

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class InMemorySecret:
    """Store sensitive data encrypted in RAM using AES-GCM."""

    def __init__(self, data: bytes) -> None:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be bytes")
        self._key = AESGCM.generate_key(bit_length=128)
        self._nonce = os.urandom(12)
        self._cipher = AESGCM(self._key)
        self._encrypted = self._cipher.encrypt(self._nonce, bytes(data), None)

    def get_bytes(self) -> bytes:
        """Decrypt and return the plaintext bytes."""
        if self._cipher is None:
            raise RuntimeError("Secret has been wiped")
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
