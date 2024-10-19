# nostr/key_manager.py

import base64
import traceback
from typing import Optional

from bip_utils import Bip39SeedGenerator
from bip85.bip85 import BIP85
from cryptography.fernet import Fernet, InvalidToken
from bech32 import bech32_encode, convertbits

from .logging_config import configure_logging
from utils.key_derivation import derive_key_from_parent_seed

# Add the missing import for Keys and NIP4Encrypt
from monstr.encrypt import Keys, NIP4Encrypt  # Ensure monstr.encrypt is installed and accessible

logger = configure_logging()

def encode_bech32(prefix: str, key_hex: str) -> str:
    """
    Encodes a hex key into Bech32 format with the given prefix.

    :param prefix: The Bech32 prefix (e.g., 'nsec', 'npub').
    :param key_hex: The key in hexadecimal format.
    :return: The Bech32-encoded string.
    """
    try:
        key_bytes = bytes.fromhex(key_hex)
        data = convertbits(key_bytes, 8, 5, pad=True)
        return bech32_encode(prefix, data)
    except Exception as e:
        logger.error(f"Failed to encode {prefix}: {e}")
        logger.error(traceback.format_exc())
        raise

class KeyManager:
    """
    Manages key generation, encoding, and derivation for NostrClient.
    """

    def __init__(self, parent_seed: str):
        self.parent_seed = parent_seed
        self.keys = None
        self.nsec = None
        self.npub = None
        self.initialize_keys()

    def initialize_keys(self):
        """
        Derives Nostr keys using BIP85 and initializes Keys.
        """
        try:
            logger.debug("Starting key initialization")
            seed_bytes = Bip39SeedGenerator(self.parent_seed).Generate()
            bip85 = BIP85(seed_bytes)
            entropy = bip85.derive_entropy(app_no=1237, language_code=0, words_num=24, index=0)

            if len(entropy) != 32:
                logger.error(f"Derived entropy length is {len(entropy)} bytes; expected 32 bytes.")
                raise ValueError("Invalid entropy length.")

            privkey_hex = entropy.hex()
            self.keys = Keys(priv_k=privkey_hex)  # Now Keys is defined via the import
            logger.debug("Nostr Keys initialized successfully.")

            self.nsec = encode_bech32('nsec', privkey_hex)
            logger.debug(f"Nostr Private Key (nsec): {self.nsec}")

            public_key_hex = self.keys.public_key_hex()
            self.npub = encode_bech32('npub', public_key_hex)
            logger.debug(f"Nostr Public Key (npub): {self.npub}")

        except Exception as e:
            logger.error(f"Key initialization failed: {e}")
            logger.error(traceback.format_exc())
            raise

    def get_npub(self) -> str:
        """
        Returns the Nostr public key (npub).

        :return: The npub as a string.
        """
        if self.npub:
            logger.debug(f"Returning npub: {self.npub}")
            return self.npub
        else:
            logger.error("Nostr public key (npub) is not available.")
            raise ValueError("Nostr public key (npub) is not available.")

    def derive_encryption_key(self) -> bytes:
        """
        Derives the encryption key using the parent seed.

        :return: The derived encryption key.
        """
        try:
            key = derive_key_from_parent_seed(self.parent_seed)
            logger.debug("Encryption key derived successfully.")
            return key
        except Exception as e:
            logger.error(f"Failed to derive encryption key: {e}")
            logger.error(traceback.format_exc())
            raise
