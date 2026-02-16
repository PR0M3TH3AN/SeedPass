"""Key validation helper functions."""

import logging
from cryptography.hazmat.primitives import serialization
from pgpy import PGPKey
import pyotp
from nostr.coincurve_keys import Keys
from mnemonic import Mnemonic

logger = logging.getLogger(__name__)


def validate_totp_secret(secret: str) -> bool:
    """Return True if ``secret`` is a valid Base32 TOTP secret."""
    try:
        pyotp.TOTP(secret).at(0)
        return True
    except Exception as e:
        logger.debug(f"Invalid TOTP secret: {e}")
        return False


def validate_ssh_key_pair(priv_pem: str, pub_pem: str) -> bool:
    """Ensure ``priv_pem`` corresponds to ``pub_pem``."""
    try:
        priv = serialization.load_pem_private_key(priv_pem.encode(), password=None)
        derived = (
            priv.public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )
        return derived == pub_pem
    except Exception as e:
        logger.debug(f"SSH key validation failed: {e}")
        return False


def validate_pgp_private_key(priv_key: str, fingerprint: str) -> bool:
    """Return True if ``priv_key`` matches ``fingerprint``."""
    try:
        key, _ = PGPKey.from_blob(priv_key)
        return key.fingerprint == fingerprint
    except Exception as e:
        logger.debug(f"PGP key validation failed: {e}")
        return False


def validate_nostr_keys(npub: str, nsec: str) -> bool:
    """Return True if ``nsec`` decodes to ``npub``."""
    try:
        priv_hex = Keys.bech32_to_hex(nsec)
        derived = Keys(priv_k=priv_hex)
        encoded = Keys.hex_to_bech32(derived.public_key_hex(), "npub")
        return encoded == npub
    except Exception as e:
        logger.debug(f"Nostr key validation failed: {e}")
        return False


def validate_seed_phrase(mnemonic: str) -> bool:
    """Return True if ``mnemonic`` is a valid BIP-39 seed phrase."""
    try:
        return Mnemonic("english").check(mnemonic)
    except Exception as e:
        logger.debug(f"Seed phrase validation failed: {e}")
        return False
