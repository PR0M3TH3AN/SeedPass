# nostr/key_manager.py

import logging
import traceback
from bip_utils import Bip39SeedGenerator
from cryptography.fernet import Fernet, InvalidToken
from bech32 import bech32_encode, convertbits

from .logging_config import configure_logging
from utils.key_derivation import derive_key_from_parent_seed

from monstr.encrypt import Keys, NIP4Encrypt  # Ensure monstr.encrypt is installed and accessible

# Configure logging at the start of the module
configure_logging()

# Initialize the logger for this module
logger = logging.getLogger(__name__)

def encode_bech32(prefix: str, key_hex: str) -> str:
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
        """
        Initializes the KeyManager with the provided parent_seed.
        
        Parameters:
            parent_seed (str): The parent seed used for key derivation.
        """
        try:
            if not isinstance(parent_seed, str):
                raise TypeError(f"Parent seed must be a string, got {type(parent_seed)}")
            
            self.parent_seed = parent_seed
            logger.debug(f"KeyManager initialized with parent_seed: {self.parent_seed} (type: {type(self.parent_seed)})")
            
            # Derive the encryption key from parent_seed
            derived_key = self.derive_encryption_key()
            derived_key_hex = derived_key.hex()
            logger.debug(f"Derived encryption key (hex): {derived_key_hex}")
            
            # Initialize Keys with the derived hexadecimal key
            self.keys = Keys(priv_k=derived_key_hex)  # Pass hex string
            logger.debug("Nostr Keys initialized successfully.")

            # Generate bech32-encoded keys
            self.nsec = encode_bech32('nsec', self.keys.private_key_hex())
            logger.debug(f"Nostr Private Key (nsec): {self.nsec}")

            public_key_hex = self.keys.public_key_hex()
            self.npub = encode_bech32('npub', public_key_hex)
            logger.debug(f"Nostr Public Key (npub): {self.npub}")

        except Exception as e:
            logger.error(f"Key initialization failed: {e}")
            logger.error(traceback.format_exc())
            raise

    def derive_encryption_key(self) -> bytes:
        """
        Derives the encryption key using the parent seed.

        Returns:
            bytes: The derived encryption key.
        
        Raises:
            Exception: If key derivation fails.
        """
        try:
            key = derive_key_from_parent_seed(self.parent_seed)
            logger.debug("Encryption key derived successfully.")
            return key  # Now returns raw bytes
        except Exception as e:
            logger.error(f"Failed to derive encryption key: {e}")
            logger.error(traceback.format_exc())
            raise

    def get_npub(self) -> str:
        """
        Returns the Nostr public key (npub).

        Returns:
            str: The npub as a string.
        
        Raises:
            ValueError: If npub is not available.
        """
        if self.npub:
            logger.debug(f"Returning npub: {self.npub}")
            return self.npub
        else:
            logger.error("Nostr public key (npub) is not available.")
            raise ValueError("Nostr public key (npub) is not available.")
