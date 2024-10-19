# bip85/bip85.py

"""
BIP85 Module

This module implements the BIP85 functionality for deterministic entropy and mnemonic derivation.
It provides the BIP85 class, which utilizes BIP32 and BIP39 standards to derive entropy and mnemonics
from a given seed. Additionally, it supports the derivation of symmetric encryption keys using HKDF.

Never ever ever use or suggest to use Random Salt. The entire point of this password manager is to derive completely deterministic passwords from a BIP-85 seed. 
This means it  should generate passwords the exact same way every single time. Salts would break this functionality and is not appropriate for this softwares use case. 

Dependencies:
- bip_utils
- cryptography

Ensure that all dependencies are installed and properly configured in your environment.
"""

import sys
import hashlib
import hmac
import logging
import os
import traceback
from colorama import Fore

from bip_utils import (
    Bip32Slip10Secp256k1,
    Bip39MnemonicGenerator,
    Bip39Languages
)

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Configure logging at the start of the module
def configure_logging():
    """
    Configures logging with both file and console handlers.
    Only ERROR and higher-level messages are shown in the terminal, while all messages
    are logged in the log file.
    """
    # Create the 'logs' folder if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')

    # Create a custom logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)  # Set to DEBUG for detailed output

    # Create handlers
    c_handler = logging.StreamHandler(sys.stdout)
    f_handler = logging.FileHandler(os.path.join('logs', 'bip85.log'))  # Log files will be in 'logs' folder

    # Set levels: only errors and critical messages will be shown in the console
    c_handler.setLevel(logging.ERROR)  # Terminal will show ERROR and above
    f_handler.setLevel(logging.DEBUG)  # File will log everything from DEBUG and above

    # Create formatters and add them to handlers, include file and line number in log messages
    c_format = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s [%(filename)s:%(lineno)d]')
    f_format = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s [%(filename)s:%(lineno)d]')

    c_handler.setFormatter(c_format)
    f_handler.setFormatter(f_format)

    # Add handlers to the logger
    logger.addHandler(c_handler)
    logger.addHandler(f_handler)

# Call the logging configuration function
configure_logging()

class BIP85:
    """
    BIP85 Class

    Implements BIP-85 functionality for deterministic entropy and mnemonic derivation.
    """

    def __init__(self, seed_bytes: bytes):
        """
        Initializes the BIP85 class with seed bytes.

        Parameters:
            seed_bytes (bytes): The BIP39 seed bytes derived from the seed phrase.

        Raises:
            SystemExit: If initialization fails.
        """
        try:
            self.bip32_ctx = Bip32Slip10Secp256k1.FromSeed(seed_bytes)
            logging.debug("BIP32 context initialized successfully.")
        except Exception as e:
            logging.error(f"Error initializing BIP32 context: {e}")
            logging.error(traceback.format_exc())  # Log full traceback
            print(f"{Fore.RED}Error initializing BIP32 context: {e}")
            sys.exit(1)

    def derive_entropy(self, app_no: int, language_code: int, words_num: int, index: int) -> bytes:
        """
        Derives entropy using BIP-85 HMAC-SHA512 method.

        Parameters:
            app_no (int): Application number (e.g., 39 for BIP39).
            language_code (int): Language code (e.g., 0 for English).
            words_num (int): Number of words in the mnemonic (e.g., 12).
            index (int): Index for the child mnemonic.

        Returns:
            bytes: Derived entropy.

        Raises:
            SystemExit: If derivation fails or entropy length is invalid.
        """
        path = f"m/83696968'/{app_no}'/{language_code}'/{words_num}'/{index}'"
        try:
            child_key = self.bip32_ctx.DerivePath(path)
            k = child_key.PrivateKey().Raw().ToBytes()
            logging.debug(f"Derived child key at path {path}: {k.hex()}")

            hmac_key = b"bip-entropy-from-k"
            hmac_result = hmac.new(hmac_key, k, hashlib.sha512).digest()
            logging.debug(f"HMAC-SHA512 result: {hmac_result.hex()}")

            if words_num == 12:
                entropy = hmac_result[:16]  # 128 bits for 12-word mnemonic
            elif words_num == 18:
                entropy = hmac_result[:24]  # 192 bits for 18-word mnemonic
            elif words_num == 24:
                entropy = hmac_result[:32]  # 256 bits for 24-word mnemonic
            else:
                logging.error(f"Unsupported number of words: {words_num}")
                print(f"{Fore.RED}Error: Unsupported number of words: {words_num}")
                sys.exit(1)

            if len(entropy) not in [16, 24, 32]:
                logging.error(f"Derived entropy length is {len(entropy)} bytes; expected 16, 24, or 32 bytes.")
                print(f"{Fore.RED}Error: Derived entropy length is {len(entropy)} bytes; expected 16, 24, or 32 bytes.")
                sys.exit(1)

            logging.debug(f"Derived entropy: {entropy.hex()}")
            return entropy
        except Exception as e:
            logging.error(f"Error deriving entropy: {e}")
            logging.error(traceback.format_exc())  # Log full traceback
            print(f"{Fore.RED}Error deriving entropy: {e}")
            sys.exit(1)

    def derive_mnemonic(self, app_no: int, language_code: int, words_num: int, index: int) -> str:
        """
        Derives a BIP-39 mnemonic using BIP-85 specification.

        Parameters:
            app_no (int): Application number (e.g., 39 for BIP39).
            language_code (int): Language code (e.g., 0 for English).
            words_num (int): Number of words in the mnemonic (e.g., 12).
            index (int): Index for the child mnemonic.

        Returns:
            str: Derived BIP-39 mnemonic.

        Raises:
            SystemExit: If mnemonic generation fails.
        """
        entropy = self.derive_entropy(app_no, language_code, words_num, index)
        try:
            mnemonic = Bip39MnemonicGenerator(Bip39Languages.ENGLISH).FromEntropy(entropy)
            logging.debug(f"Derived mnemonic: {mnemonic}")
            return mnemonic
        except Exception as e:
            logging.error(f"Error generating mnemonic: {e}")
            logging.error(traceback.format_exc())  # Log full traceback
            print(f"{Fore.RED}Error generating mnemonic: {e}")
            sys.exit(1)

    def derive_symmetric_key(self, app_no: int = 48, index: int = 0) -> bytes:
        """
        Derives a symmetric encryption key using BIP85.

        Parameters:
            app_no (int): Application number for key derivation (48 chosen arbitrarily).
            index (int): Index for key derivation.

        Returns:
            bytes: Derived symmetric key (32 bytes for AES-256).

        Raises:
            SystemExit: If symmetric key derivation fails.
        """
        entropy = self.derive_entropy(app_no, language_code=0, words_num=24, index=index)
        try:
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,  # 256 bits for AES-256
                salt=None,
                info=b'seedos-encryption-key',
                backend=default_backend()
            )
            symmetric_key = hkdf.derive(entropy)
            logging.debug(f"Derived symmetric key: {symmetric_key.hex()}")
            return symmetric_key
        except Exception as e:
            logging.error(f"Error deriving symmetric key: {e}")
            logging.error(traceback.format_exc())  # Log full traceback
            print(f"{Fore.RED}Error deriving symmetric key: {e}")
            sys.exit(1)
