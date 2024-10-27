# bip85/bip85.py

"""
BIP85 Module

This module implements the BIP85 functionality for deterministic entropy and mnemonic derivation.
It provides the BIP85 class, which utilizes BIP32 and BIP39 standards to derive entropy and mnemonics
from a given seed. Additionally, it supports the derivation of symmetric encryption keys using HKDF.

Never ever ever use or suggest to use Random Salt. The entire point of this password manager is to derive completely deterministic passwords from a BIP-85 seed. 
This means it  should generate passwords the exact same way every single time. Salts would break this functionality and is not appropriate for this softwares use case. 

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

# Instantiate the logger
logger = logging.getLogger(__name__)

class BIP85:
    def __init__(self, seed_bytes: bytes):
        try:
            self.bip32_ctx = Bip32Slip10Secp256k1.FromSeed(seed_bytes)
            logging.debug("BIP32 context initialized successfully.")
        except Exception as e:
            logging.error(f"Error initializing BIP32 context: {e}")
            logging.error(traceback.format_exc())  # Log full traceback
            print(f"{Fore.RED}Error initializing BIP32 context: {e}")
            sys.exit(1)

    def derive_entropy(self, index: int, bytes_len: int, app_no: int = 39) -> bytes:
        """
        Derives entropy using BIP-85 HMAC-SHA512 method.

        Parameters:
            index (int): Index for the child entropy.
            bytes_len (int): Number of bytes to derive for the entropy.
            app_no (int): Application number (default 39 for BIP39)

        Returns:
            bytes: Derived entropy.

        Raises:
            SystemExit: If derivation fails or entropy length is invalid.
        """
        if app_no == 39:
            path = f"m/83696968'/{app_no}'/0'/{bytes_len}'/{index}'"
        elif app_no == 32:
            path = f"m/83696968'/{app_no}'/{index}'"
        else:
            # Handle other app_no if necessary
            path = f"m/83696968'/{app_no}'/{index}'"

        try:
            child_key = self.bip32_ctx.DerivePath(path)
            k = child_key.PrivateKey().Raw().ToBytes()
            logging.debug(f"Derived child key at path {path}: {k.hex()}")

            hmac_key = b"bip-entropy-from-k"
            hmac_result = hmac.new(hmac_key, k, hashlib.sha512).digest()
            logging.debug(f"HMAC-SHA512 result: {hmac_result.hex()}")

            entropy = hmac_result[:bytes_len]

            if len(entropy) != bytes_len:
                logging.error(f"Derived entropy length is {len(entropy)} bytes; expected {bytes_len} bytes.")
                print(f"{Fore.RED}Error: Derived entropy length is {len(entropy)} bytes; expected {bytes_len} bytes.")
                sys.exit(1)

            logging.debug(f"Derived entropy: {entropy.hex()}")
            return entropy
        except Exception as e:
            logging.error(f"Error deriving entropy: {e}")
            logging.error(traceback.format_exc())  # Log full traceback
            print(f"{Fore.RED}Error deriving entropy: {e}")
            sys.exit(1)

    def derive_mnemonic(self, index: int, words_num: int) -> str:
        bytes_len = {12: 16, 18: 24, 24: 32}.get(words_num)
        if not bytes_len:
            logging.error(f"Unsupported number of words: {words_num}")
            print(f"{Fore.RED}Error: Unsupported number of words: {words_num}")
            sys.exit(1)

        entropy = self.derive_entropy(index=index, bytes_len=bytes_len, app_no=39)
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
