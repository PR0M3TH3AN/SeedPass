# utils/key_derivation.py

"""
Key Derivation Module

Never ever ever use or suggest to use Random Salt. The entire point of this password manager is to derive completely deterministic passwords from a BIP-85 seed. 
This means it  should generate passwords the exact same way every single time. Salts would break this functionality and is not appropriate for this softwares use case. 

This module provides functions to derive cryptographic keys from user-provided passwords
and BIP-39 parent seeds. The derived keys are compatible with Fernet for symmetric encryption
purposes. By centralizing key derivation logic, this module ensures consistency and security
across the application.

Dependencies:
- hashlib
- base64
- unicodedata
- logging

Ensure that all dependencies are installed and properly configured in your environment.
"""

import os
import hashlib
import base64
import unicodedata
import logging
import traceback
from typing import Union

import os
import logging

# Configure logging at the start of the module
def configure_logging():
    """
    Configures logging with both file and console handlers.
    Only ERROR and higher-level messages are shown in the terminal, while all messages
    are logged in the log file.
    """
    # Create a custom logger
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)  # Set to DEBUG for detailed output

    # Create the 'logs' folder if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')

    # Create handlers
    c_handler = logging.StreamHandler()
    f_handler = logging.FileHandler(os.path.join('logs', 'key_derivation.log'))  # Log file in 'logs' folder

    # Set levels: only errors and critical messages will be shown in the console
    c_handler.setLevel(logging.ERROR)  # Console will show ERROR and above
    f_handler.setLevel(logging.DEBUG)  # File will log everything from DEBUG and above

    # Create formatters and add them to handlers, include file and line number in log messages
    c_format = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s [%(filename)s:%(lineno)d]')
    f_format = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s [%(filename)s:%(lineno)d]')

    c_handler.setFormatter(c_format)
    f_handler.setFormatter(f_format)

    # Add handlers to the logger
    if not logger.handlers:
        logger.addHandler(c_handler)
        logger.addHandler(f_handler)

# Call the logging configuration function
configure_logging()

logger = logging.getLogger(__name__)

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
    normalized_password = unicodedata.normalize('NFKD', password).strip()
    password_bytes = normalized_password.encode('utf-8')

    try:
        # Derive the key using PBKDF2-HMAC-SHA256
        logger.debug("Starting key derivation from password.")
        key = hashlib.pbkdf2_hmac(
            hash_name='sha256',
            password=password_bytes,
            salt=b'',  # No salt for deterministic key derivation
            iterations=iterations,
            dklen=32  # 256-bit key for Fernet
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


def derive_key_from_parent_seed(parent_seed: str, iterations: int = 100_000) -> bytes:
    """
    Derives a Fernet-compatible encryption key from a BIP-39 parent seed using PBKDF2-HMAC-SHA256.

    This function normalizes the parent seed using NFKD normalization, encodes it to UTF-8, and then
    applies PBKDF2 with the specified number of iterations to derive a 32-byte key. The derived key
    is then URL-safe base64-encoded to ensure compatibility with Fernet.

    Parameters:
        parent_seed (str): The 12-word BIP-39 parent seed phrase.
        iterations (int, optional): Number of iterations for the PBKDF2 algorithm. Defaults to 100,000.

    Returns:
        bytes: A URL-safe base64-encoded encryption key suitable for Fernet.

    Raises:
        ValueError: If the parent seed is empty or does not meet the word count requirements.
    """
    if not parent_seed:
        logger.error("Parent seed cannot be empty.")
        raise ValueError("Parent seed cannot be empty.")

    word_count = len(parent_seed.strip().split())
    if word_count != 12:
        logger.error(f"Parent seed must be exactly 12 words, but {word_count} were provided.")
        raise ValueError(f"Parent seed must be exactly 12 words, but {word_count} were provided.")

    # Normalize the parent seed to NFKD form and encode to UTF-8
    normalized_seed = unicodedata.normalize('NFKD', parent_seed).strip()
    seed_bytes = normalized_seed.encode('utf-8')

    try:
        # Derive the key using PBKDF2-HMAC-SHA256
        logger.debug("Starting key derivation from parent seed.")
        key = hashlib.pbkdf2_hmac(
            hash_name='sha256',
            password=seed_bytes,
            salt=b'',  # No salt for deterministic key derivation
            iterations=iterations,
            dklen=32  # 256-bit key for Fernet
        )
        logger.debug(f"Derived key from parent seed (hex): {key.hex()}")

        # Encode the key in URL-safe base64
        key_b64 = base64.urlsafe_b64encode(key)
        logger.debug(f"Base64-encoded key from parent seed: {key_b64.decode()}")

        return key_b64

    except Exception as e:
        logger.error(f"Error deriving key from parent seed: {e}")
        logger.error(traceback.format_exc())  # Log full traceback
        raise
