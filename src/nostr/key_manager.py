# nostr/key_manager.py

import hashlib
import logging
import traceback
from bech32 import bech32_encode, convertbits

from local_bip85.bip85 import BIP85
from bip_utils import Bip39SeedGenerator
from monstr.encrypt import Keys

logger = logging.getLogger(__name__)

class KeyManager:
    """
    Manages key generation, encoding, and derivation for NostrClient.
    """

    def __init__(self, parent_seed: str, fingerprint: str):
        """
        Initializes the KeyManager with the provided parent_seed and fingerprint.

        Parameters:
            parent_seed (str): The parent seed used for key derivation.
            fingerprint (str): The fingerprint to differentiate key derivations.
        """
        try:
            if not isinstance(parent_seed, str):
                raise TypeError(f"Parent seed must be a string, got {type(parent_seed)}")
            if not isinstance(fingerprint, str):
                raise TypeError(f"Fingerprint must be a string, got {type(fingerprint)}")

            self.parent_seed = parent_seed
            self.fingerprint = fingerprint
            logger.debug(f"KeyManager initialized with parent_seed and fingerprint.")

            # Initialize BIP85
            self.bip85 = self.initialize_bip85()

            # Generate Nostr keys using the fingerprint
            self.keys = self.generate_nostr_keys()
            logger.debug("Nostr Keys initialized successfully.")

        except Exception as e:
            logger.error(f"Key initialization failed: {e}")
            logger.error(traceback.format_exc())
            raise

    def initialize_bip85(self):
        """
        Initializes BIP85 with the parent seed.

        Returns:
            BIP85: An instance of the BIP85 class.
        """
        try:
            seed_bytes = Bip39SeedGenerator(self.parent_seed).Generate()
            bip85 = BIP85(seed_bytes)
            logger.debug("BIP85 initialized successfully.")
            return bip85
        except Exception as e:
            logger.error(f"Failed to initialize BIP85: {e}")
            logger.error(traceback.format_exc())
            raise

    def generate_nostr_keys(self) -> Keys:
        """
        Derives a unique Nostr key pair for the given fingerprint using BIP-85.

        Returns:
            Keys: An instance of Keys containing the Nostr key pair.
        """
        try:
            # Convert fingerprint to an integer index (using a hash function)
            index = int(hashlib.sha256(self.fingerprint.encode()).hexdigest(), 16) % (2**31)

            # Derive entropy for Nostr key (32 bytes)
            entropy_bytes = self.bip85.derive_entropy(
                index=index,
                bytes_len=32  # Adjust parameter name and value as per your method signature
            )

            # Generate Nostr key pair from entropy
            private_key_hex = entropy_bytes.hex()
            keys = Keys(priv_k=private_key_hex)
            logger.debug(f"Nostr keys generated for fingerprint {self.fingerprint}.")
            return keys
        except Exception as e:
            logger.error(f"Failed to generate Nostr keys: {e}")
            logger.error(traceback.format_exc())
            raise

    def get_public_key_hex(self) -> str:
        """
        Returns the public key in hexadecimal format.

        Returns:
            str: The public key in hex.
        """
        return self.keys.public_key_hex()

    def get_private_key_hex(self) -> str:
        """
        Returns the private key in hexadecimal format.

        Returns:
            str: The private key in hex.
        """
        return self.keys.private_key_hex()
    
    def get_npub(self) -> str:
        """
        Returns the npub (Bech32 encoded public key).

        Returns:
            str: The npub string.
        """
        try:
            pub_key_hex = self.get_public_key_hex()
            pub_key_bytes = bytes.fromhex(pub_key_hex)
            data = convertbits(pub_key_bytes, 8, 5, True)
            npub = bech32_encode('npub', data)
            return npub
        except Exception as e:
            logger.error(f"Failed to generate npub: {e}")
            logger.error(traceback.format_exc())
            raise
