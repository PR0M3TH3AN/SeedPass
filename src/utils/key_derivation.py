# utils/key_derivation.py

"""
Key Derivation Module

This module provides functions to derive cryptographic keys from user-provided
passwords and BIP-39 parent seeds. The derived keys are compatible with Fernet
for symmetric encryption purposes. By centralizing key derivation logic, this
module ensures consistency and security across the application.

Ensure that all dependencies are installed and properly configured in your
environment.
"""

import os
import hashlib
import base64
import unicodedata
import logging
import hmac
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Union, Dict, Any

from bip_utils import Bip39SeedGenerator
from local_bip85 import BIP85
from .key_hierarchy import kd

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Instantiate the logger
logger = logging.getLogger(__name__)


class EncryptionMode(Enum):
    """Supported key derivation modes for database encryption."""

    SEED_ONLY = "seed-only"


DEFAULT_ENCRYPTION_MODE = EncryptionMode.SEED_ONLY

# Purpose constant for TOTP secret derivation using BIP85
TOTP_PURPOSE = 39


@dataclass
class KdfConfig:
    """Configuration block describing how a key was derived."""

    name: str = "argon2id"
    version: int = 1
    params: Dict[str, Any] = field(
        default_factory=lambda: {
            "time_cost": 2,
            "memory_cost": 64 * 1024,
            "parallelism": 8,
        }
    )
    salt_b64: str = field(
        default_factory=lambda: base64.b64encode(os.urandom(16)).decode()
    )


CURRENT_KDF_VERSION = 1


def derive_key_from_password(
    password: str, fingerprint: Union[str, bytes], iterations: int = 100_000
) -> bytes:
    """
    Derives a Fernet-compatible encryption key from the provided password using PBKDF2-HMAC-SHA256.

    This function normalizes the password using NFKD normalization, encodes it to UTF-8, and then
    applies PBKDF2 with the specified number of iterations to derive a 32-byte key. The derived key
    is then URL-safe base64-encoded to ensure compatibility with Fernet.

    Parameters:
        password (str): The user's password.
        fingerprint (str | bytes): Seed fingerprint or precomputed salt.
        iterations (int, optional): Number of iterations for the PBKDF2 algorithm.
            Defaults to 100,000.

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

    # Derive a deterministic salt from the fingerprint
    if isinstance(fingerprint, bytes):
        salt = fingerprint
    else:
        salt = hashlib.sha256(fingerprint.encode()).digest()[:16]

    try:
        # Derive the key using PBKDF2-HMAC-SHA256
        logger.debug("Starting key derivation from password.")
        key = hashlib.pbkdf2_hmac(
            hash_name="sha256",
            password=password_bytes,
            salt=salt,
            iterations=iterations,
            dklen=32,  # 256-bit key for Fernet
        )
        logger.debug("Key derived from password using PBKDF2.")

        # Encode the key in URL-safe base64
        key_b64 = base64.urlsafe_b64encode(key)
        logger.debug("Derived key encoded in URL-safe base64.")

        return key_b64

    except Exception as e:
        logger.error(f"Error deriving key from password: {e}", exc_info=True)
        raise


def derive_key_from_password_argon2(password: str, kdf: KdfConfig) -> bytes:
    """Derive an encryption key from a password using Argon2id.

    Parameters
    ----------
    password:
        The user's password.
    kdf:
        :class:`KdfConfig` instance describing salt and tuning parameters.
    """

    if not password:
        logger.error("Password cannot be empty.")
        raise ValueError("Password cannot be empty.")

    normalized = unicodedata.normalize("NFKD", password).strip().encode("utf-8")
    try:
        from argon2.low_level import hash_secret_raw, Type

        params = kdf.params or {}
        salt = base64.b64decode(kdf.salt_b64)
        key = hash_secret_raw(
            secret=normalized,
            salt=salt,
            time_cost=int(params.get("time_cost", 2)),
            memory_cost=int(params.get("memory_cost", 64 * 1024)),
            parallelism=int(params.get("parallelism", 8)),
            hash_len=32,
            type=Type.ID,
        )
        return base64.urlsafe_b64encode(key)
    except Exception as e:  # pragma: no cover - pass through errors
        logger.error(f"Error deriving key with Argon2id: {e}", exc_info=True)
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
        logger.error(f"Failed to derive key using HKDF: {e}", exc_info=True)
        raise


def derive_index_key_seed_only(seed: str) -> bytes:
    """Derive the index encryption key using the v1 hierarchy."""
    seed_bytes = Bip39SeedGenerator(seed).Generate()
    master = kd(seed_bytes, b"seedpass:v1:master")
    key = kd(master, b"seedpass:v1:storage")
    return base64.urlsafe_b64encode(key)


def derive_index_key(seed: str) -> bytes:
    """Derive the index encryption key."""
    return derive_index_key_seed_only(seed)


def derive_totp_secret(seed: Union[str, bytes], index: int) -> str:
    """Derive a base32-encoded TOTP secret from a seed or raw key."""
    try:
        if isinstance(seed, (bytes, bytearray)):
            seed_bytes = bytes(seed)
        else:
            seed_bytes = Bip39SeedGenerator(seed).Generate()
        bip85 = BIP85(seed_bytes)

        totp_int = int.from_bytes(b"TOTP", "big")
        path = f"m/83696968'/{TOTP_PURPOSE}'/{totp_int}'/{index}'"
        child_key = bip85.bip32_ctx.DerivePath(path)
        key_bytes = child_key.PrivateKey().Raw().ToBytes()
        entropy = hmac.new(b"bip-entropy-from-k", key_bytes, hashlib.sha512).digest()

        hashed = hashlib.sha256(entropy[:32]).digest()
        secret = base64.b32encode(hashed[:20]).decode("utf-8")
        logger.debug(f"Derived TOTP secret for index {index}.")
        return secret
    except Exception as e:
        logger.error(f"Failed to derive TOTP secret: {e}", exc_info=True)
        raise


def calibrate_argon2_time_cost(
    cfg_mgr: "ConfigManager",
    *,
    target_ms: float = 500.0,
    max_time_cost: int = 6,
) -> int:
    """Calibrate Argon2 ``time_cost`` based on device performance.

    Runs :func:`derive_key_from_password_argon2` with increasing ``time_cost``
    until the runtime meets or exceeds ``target_ms``. The chosen ``time_cost``
    is stored in ``cfg_mgr`` via ``set_argon2_time_cost`` and returned.

    Parameters
    ----------
    cfg_mgr:
        Instance of :class:`~seedpass.core.config_manager.ConfigManager` used to
        persist the calibrated ``time_cost``.
    target_ms:
        Desired minimum execution time in milliseconds for one Argon2 hash.
    max_time_cost:
        Upper bound for ``time_cost`` to prevent excessively long calibration.

    Returns
    -------
    int
        Selected ``time_cost`` value.
    """

    password = "benchmark"
    salt = base64.b64encode(b"argon2-calibration").decode()
    time_cost = 1
    elapsed_ms = 0.0
    while time_cost <= max_time_cost:
        start = time.perf_counter()
        cfg = KdfConfig(
            params={"time_cost": time_cost, "memory_cost": 8, "parallelism": 1},
            salt_b64=salt,
        )
        derive_key_from_password_argon2(password, cfg)
        elapsed_ms = (time.perf_counter() - start) * 1000
        if elapsed_ms >= target_ms:
            break
        time_cost += 1

    cfg_mgr.set_argon2_time_cost(time_cost)
    if cfg_mgr.load_config(require_pin=False).get("verbose_timing"):
        logger.info("Calibrated Argon2 time_cost=%s (%.2f ms)", time_cost, elapsed_ms)
    return time_cost
