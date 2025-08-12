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
from typing import Union

from colorama import Fore

from bip_utils import Bip32Slip10Secp256k1, Bip39MnemonicGenerator, Bip39Languages

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Instantiate the logger
logger = logging.getLogger(__name__)


class Bip85Error(Exception):
    """Exception raised for BIP85-related errors."""

    pass


class BIP85:
    def __init__(self, seed_or_xprv: Union[bytes, str]):
        """Initialize from seed bytes or an ``xprv`` string.

        Parameters:
            seed_or_xprv (Union[bytes, str]): Either raw BIP39 seed bytes
                or a BIP32 extended private key (``xprv``) string.
        """

        try:
            if isinstance(seed_or_xprv, (bytes, bytearray)):
                self.bip32_ctx = Bip32Slip10Secp256k1.FromSeed(seed_or_xprv)
            else:
                self.bip32_ctx = Bip32Slip10Secp256k1.FromExtendedKey(seed_or_xprv)
            logging.debug("BIP32 context initialized successfully.")
        except Exception as e:
            logging.error(f"Error initializing BIP32 context: {e}", exc_info=True)
            print(f"{Fore.RED}Error initializing BIP32 context: {e}")
            raise Bip85Error(f"Error initializing BIP32 context: {e}")

    def derive_entropy(
        self,
        index: int,
        entropy_bytes: int,
        app_no: int = 39,
        word_count: int | None = None,
    ) -> bytes:
        """Derive entropy using the BIP-85 HMAC-SHA512 method.

        Parameters:
            index (int): Index for the child entropy.
            entropy_bytes (int): Number of bytes of entropy to derive.
            app_no (int): Application number (default 39 for BIP39).
            word_count (int | None): Number of words used in the derivation path
                for BIP39. If ``None`` and ``app_no`` is ``39``, ``word_count``
                defaults to ``entropy_bytes``. The final segment of the
                derivation path becomes ``m/83696968'/39'/0'/word_count'/index'``.

        Returns:
            bytes: Derived entropy of length ``entropy_bytes``.

        Raises:
            SystemExit: If derivation fails or the derived entropy length is
                invalid.
        """
        if app_no == 39:
            if word_count is None:
                word_count = entropy_bytes
            path = f"m/83696968'/{app_no}'/0'/{word_count}'/{index}'"
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

            entropy = hmac_result[:entropy_bytes]

            if len(entropy) != entropy_bytes:
                logging.error(
                    f"Derived entropy length is {len(entropy)} bytes; expected {entropy_bytes} bytes."
                )
                print(
                    f"{Fore.RED}Error: Derived entropy length is {len(entropy)} bytes; expected {entropy_bytes} bytes."
                )
                raise Bip85Error(
                    f"Derived entropy length is {len(entropy)} bytes; expected {entropy_bytes} bytes."
                )

            logging.debug(f"Derived entropy: {entropy.hex()}")
            return entropy
        except Exception as e:
            logging.error(f"Error deriving entropy: {e}", exc_info=True)
            print(f"{Fore.RED}Error deriving entropy: {e}")
            raise Bip85Error(f"Error deriving entropy: {e}")

    def derive_mnemonic(self, index: int, words_num: int) -> str:
        entropy_bytes = {12: 16, 18: 24, 24: 32}.get(words_num)
        if not entropy_bytes:
            logging.error(f"Unsupported number of words: {words_num}")
            print(f"{Fore.RED}Error: Unsupported number of words: {words_num}")
            raise Bip85Error(f"Unsupported number of words: {words_num}")

        entropy = self.derive_entropy(
            index=index,
            entropy_bytes=entropy_bytes,
            app_no=39,
            word_count=words_num,
        )
        try:
            mnemonic = Bip39MnemonicGenerator(Bip39Languages.ENGLISH).FromEntropy(
                entropy
            )
            logging.debug(f"Derived mnemonic: {mnemonic}")
            return mnemonic.ToStr()
        except Exception as e:
            logging.error(f"Error generating mnemonic: {e}", exc_info=True)
            print(f"{Fore.RED}Error generating mnemonic: {e}")
            raise Bip85Error(f"Error generating mnemonic: {e}")

    def derive_symmetric_key(self, index: int = 0, app_no: int = 2) -> bytes:
        """Derive 32 bytes of entropy for symmetric key usage."""
        try:
            key = self.derive_entropy(index=index, entropy_bytes=32, app_no=app_no)
            logging.debug(f"Derived symmetric key: {key.hex()}")
            return key
        except Exception as e:
            logging.error(f"Error deriving symmetric key: {e}", exc_info=True)
            print(f"{Fore.RED}Error deriving symmetric key: {e}")
            raise Bip85Error(f"Error deriving symmetric key: {e}")
