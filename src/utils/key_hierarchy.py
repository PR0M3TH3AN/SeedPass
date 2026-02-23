"""Key hierarchy helper functions."""

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def kd(root: bytes, info: bytes, length: int = 32) -> bytes:
    """Derive a sub-key from ``root`` using HKDF-SHA256.

    Parameters
    ----------
    root:
        Root key material.
    info:
        Domain separation string.
    length:
        Length of the derived key in bytes. Defaults to 32.
    """

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
        backend=default_backend(),
    )
    return hkdf.derive(root)
