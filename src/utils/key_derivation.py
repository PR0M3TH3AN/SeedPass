# utils/key_derivation.py

"""
Key Derivation Module

Never ever ever use or suggest to use Random Salt. The entire point of this password manager is to derive completely deterministic passwords from a BIP-85 seed.
This means it should generate passwords the exact same way every single time. Salts would break this functionality and is not appropriate for this software's use case.

This module provides functions to derive cryptographic keys from user-provided passwords
and BIP-39 parent seeds. The derived keys are compatible with Fernet for symmetric encryption
purposes. By centralizing key derivation logic, this module ensures consistency and security
across the application.

Ensure that all dependencies are installed and properly configured in your environment.
"""

import os
import hashlib
import base64
import unicodedata
import logging
import traceback
from enum import Enum
from typing import Optional, Union
from bip_utils import Bip39SeedGenerator
from local_bip85.bip85 import BIP85

try:
    from monstr.encrypt import Keys
except ImportError:  # Fall back to local coincurve implementation
    from nostr.coincurve_keys import Keys
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Instantiate the logger
logger = logging.getLogger(__name__)


class EncryptionMode(Enum):
    """Supported key derivation modes for database encryption."""

    SEED_ONLY = "seed-only"
    SEED_PLUS_PW = "seed+pw"
    PW_ONLY = "pw-only"


DEFAULT_ENCRYPTION_MODE = EncryptionMode.SEED_ONLY


def derive_key_from_password(password: str, iterations: int = 100_000) -> bytes:
    """
    Derives a Fernet-compatible encryption key from the provided password using PBKDF2-HMAC-SHA256.

    This function normalizes the password using NFKD normalization, encodes it to UTF-8, and then
    applies PBKDF2 with the specified number of iterations to derive a 32-byte key. The derived key
    is then URL-safe base64-encoded to ensure compatibility with Fernet.

    Parameters:
        password (str): The user's password.
        iterations (int, optional): Number of iterations for the PBKDF2 algorithm. Defaults to 100,000.

    Returns:
        bytes: A URL-safe base64-encoded encryption key suitable for Fernet.

    Raises:
        ValueError: If the password is empty or too short.
    """
    if not password:
        logger.error("Password cannot be empty.")
        raise ValueError("Password cannot be empty.")

    if len(password) < 8:
        logger.warning("Password length is less than recommended (8 characters).")

    # Normalize the password to NFKD form and encode to UTF-8
    normalized_password = unicodedata.normalize("NFKD", password).strip()
    password_bytes = normalized_password.encode("utf-8")

    try:
        # Derive the key using PBKDF2-HMAC-SHA256
        logger.debug("Starting key derivation from password.")
        key = hashlib.pbkdf2_hmac(
            hash_name="sha256",
            password=password_bytes,
            salt=b"",  # No salt for deterministic key derivation
            iterations=iterations,
            dklen=32,  # 256-bit key for Fernet
        )
        logger.debug(f"Derived key (hex): {key.hex()}")

        # Encode the key in URL-safe base64
        key_b64 = base64.urlsafe_b64encode(key)
        logger.debug(f"Base64-encoded key: {key_b64.decode()}")

        return key_b64

    except Exception as e:
        logger.error(f"Error deriving key from password: {e}")
        logger.error(traceback.format_exc())  # Log full traceback
        raise


def derive_key_from_parent_seed(parent_seed: str, fingerprint: str = None) -> bytes:
    """
    Derives a 32-byte cryptographic key from a BIP-39 parent seed using HKDF.
    Optionally, include a fingerprint to differentiate key derivation per fingerprint.

    :param parent_seed: The 12-word BIP-39 seed phrase.
    :param fingerprint: An optional fingerprint to create unique keys per fingerprint.
    :return: A 32-byte derived key.
    """
    try:
        # Generate seed bytes from mnemonic
        seed = Bip39SeedGenerator(parent_seed).Generate()

        # If a fingerprint is provided, use it to differentiate the derivation
        if fingerprint:
            # Convert fingerprint to a stable integer index
            index = int(hashlib.sha256(fingerprint.encode()).hexdigest(), 16) % (2**31)
            info = f"password-manager-{index}".encode()  # Unique info for HKDF
        else:
            info = b"password-manager"

        # Derive key using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,  # No salt for deterministic derivation
            info=info,
            backend=default_backend(),
        )
        derived_key = hkdf.derive(seed)

        if len(derived_key) != 32:
            raise ValueError(
                f"Derived key length is {len(derived_key)} bytes; expected 32 bytes."
            )

        return derived_key
    except Exception as e:
        logger.error(f"Failed to derive key using HKDF: {e}")
        logger.error(traceback.format_exc())
        raise


class KeyManager:
    def __init__(self, parent_seed: str, fingerprint: str = None):
        self.parent_seed = parent_seed
        self.fingerprint = fingerprint
        self.bip85 = self.initialize_bip85()
        self.keys = self.generate_nostr_keys()

    def initialize_bip85(self):
        seed_bytes = Bip39SeedGenerator(self.parent_seed).Generate()
        bip85 = BIP85(seed_bytes)
        return bip85

    def generate_nostr_keys(self) -> Keys:
        """
        Derives a unique Nostr key pair for the given fingerprint using BIP-85.

        :return: An instance of Keys containing the Nostr key pair.
        """
        # Use a derivation path that includes the fingerprint
        # Convert fingerprint to an integer index (e.g., using a hash function)
        index = (
            int(hashlib.sha256(self.fingerprint.encode()).hexdigest(), 16) % (2**31)
            if self.fingerprint
            else 0
        )

        # Derive entropy for Nostr key (32 bytes)
        entropy_bytes = self.bip85.derive_entropy(
            app=BIP85.Applications.ENTROPY, index=index, size=32
        )

        # Generate Nostr key pair from entropy
        private_key_hex = entropy_bytes.hex()
        keys = Keys(priv_key=private_key_hex)
        return keys


def derive_index_key_seed_only(seed: str) -> bytes:
    """Derive a deterministic Fernet key from only the BIP-39 seed."""
    seed_bytes = Bip39SeedGenerator(seed).Generate()
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"password-db",
        backend=default_backend(),
    )
    key = hkdf.derive(seed_bytes)
    return base64.urlsafe_b64encode(key)


def derive_index_key_seed_plus_pw(seed: str, password: str) -> bytes:
    """Derive the index key from seed and password combined."""
    seed_bytes = Bip39SeedGenerator(seed).Generate()
    pw_bytes = unicodedata.normalize("NFKD", password).encode("utf-8")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"password-db",
        backend=default_backend(),
    )
    key = hkdf.derive(seed_bytes + b"|" + pw_bytes)
    return base64.urlsafe_b64encode(key)


def derive_index_key(
    seed: str,
    password: Optional[str] = None,
    mode: EncryptionMode = DEFAULT_ENCRYPTION_MODE,
) -> bytes:
    """Derive the index encryption key based on the selected mode."""
    if mode == EncryptionMode.SEED_ONLY:
        return derive_index_key_seed_only(seed)
    if mode == EncryptionMode.SEED_PLUS_PW:
        if password is None:
            raise ValueError("Password required for seed+pw mode")
        return derive_index_key_seed_plus_pw(seed, password)
    if mode == EncryptionMode.PW_ONLY:
        if password is None:
            raise ValueError("Password required for pw-only mode")
        return derive_key_from_password(password)
    raise ValueError(f"Unsupported encryption mode: {mode}")
