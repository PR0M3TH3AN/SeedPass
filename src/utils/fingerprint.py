# utils/fingerprint.py

"""
Fingerprint Module

This module provides functionality to generate a unique, one-way hashed fingerprint
from a given seed phrase. The fingerprint serves as an identifier for each seed,
facilitating organized and secure storage.
"""

import hashlib
import logging
import traceback
from typing import Optional

# Instantiate the logger
logger = logging.getLogger(__name__)


def generate_fingerprint(seed_phrase: str, length: int = 16) -> Optional[str]:
    """
    Generates a unique fingerprint from the provided seed phrase using SHA-256.

    Parameters:
        seed_phrase (str): The BIP-39 seed phrase.
        length (int): The desired length of the fingerprint.

    Returns:
        Optional[str]: The generated fingerprint or None if an error occurs.
    """
    try:
        # Normalize the seed phrase
        normalized_seed = seed_phrase.strip().lower()
        logger.debug(f"Normalized seed: {normalized_seed}")

        # Compute SHA-256 hash
        sha256_hash = hashlib.sha256(normalized_seed.encode("utf-8")).hexdigest()
        logger.debug(f"SHA-256 Hash: {sha256_hash}")

        # Truncate to desired length
        fingerprint = sha256_hash[:length].upper()
        logger.debug(f"Generated Fingerprint: {fingerprint}")

        return fingerprint
    except Exception as e:
        logger.error(f"Failed to generate fingerprint: {e}")
        logger.error(traceback.format_exc())
        return None
