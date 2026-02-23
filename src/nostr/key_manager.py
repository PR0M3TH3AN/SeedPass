# nostr/key_manager.py

import hashlib
import logging
from bech32 import bech32_encode, convertbits

from local_bip85.bip85 import BIP85
from bip_utils import Bip39SeedGenerator
from .coincurve_keys import Keys

# BIP-85 application numbers for Nostr key derivation
NOSTR_KEY_APP_ID = 1237
LEGACY_NOSTR_KEY_APP_ID = 0

logger = logging.getLogger(__name__)


class KeyManager:
    """Manages key generation, encoding, and derivation for ``NostrClient``."""

    def __init__(
        self, parent_seed: str, fingerprint: str, account_index: int | None = None
    ):
        """Initialize the key manager.

        Parameters
        ----------
        parent_seed:
            The BIP-39 seed used as the root for derivations.
        fingerprint:
            Seed profile fingerprint used for legacy derivations and logging.
        account_index:
            Optional explicit index for BIP-85 Nostr key derivation. When ``None``
            the index defaults to ``0``.
        """
        try:
            if not isinstance(parent_seed, str):
                raise TypeError(
                    f"Parent seed must be a string, got {type(parent_seed)}"
                )
            if not isinstance(fingerprint, str):
                raise TypeError(
                    f"Fingerprint must be a string, got {type(fingerprint)}"
                )

            self.parent_seed = parent_seed
            self.fingerprint = fingerprint
            self.account_index = account_index
            logger.debug(
                "KeyManager initialized with parent_seed, fingerprint and account index."
            )

            # Initialize BIP85
            self.bip85 = self.initialize_bip85()

            # Generate Nostr keys using the provided account index
            self.keys = self.generate_nostr_keys()
            logger.debug("Nostr Keys initialized successfully.")

        except Exception as e:
            logger.error(f"Key initialization failed: {e}", exc_info=True)
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
            logger.error(f"Failed to initialize BIP85: {e}", exc_info=True)
            raise

    def generate_nostr_keys(self) -> Keys:
        """Derive a Nostr key pair using the configured ``account_index``."""
        try:
            index = self.account_index if self.account_index is not None else 0

            entropy_bytes = self.bip85.derive_entropy(
                index=index, entropy_bytes=32, app_no=NOSTR_KEY_APP_ID
            )

            private_key_hex = entropy_bytes.hex()
            keys = Keys(priv_k=private_key_hex)
            logger.debug("Nostr keys generated for account index %s", index)
            return keys
        except Exception as e:
            logger.error(f"Failed to generate Nostr keys: {e}", exc_info=True)
            raise

    def generate_v1_nostr_keys(self) -> Keys:
        """Derive keys using the legacy fingerprint-hash method."""
        try:
            index = int(hashlib.sha256(self.fingerprint.encode()).hexdigest(), 16) % (
                2**31
            )
            entropy_bytes = self.bip85.derive_entropy(
                index=index, entropy_bytes=32, app_no=NOSTR_KEY_APP_ID
            )
            return Keys(priv_k=entropy_bytes.hex())
        except Exception as e:
            logger.error(f"Failed to generate v1 Nostr keys: {e}", exc_info=True)
            raise

    def generate_legacy_nostr_keys(self) -> Keys:
        """Derive Nostr keys using the legacy application ID."""
        try:
            entropy = self.bip85.derive_entropy(
                index=0, entropy_bytes=32, app_no=LEGACY_NOSTR_KEY_APP_ID
            )
            return Keys(priv_k=entropy.hex())
        except Exception as e:
            logger.error(f"Failed to generate legacy Nostr keys: {e}", exc_info=True)
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
            npub = bech32_encode("npub", data)
            return npub
        except Exception as e:
            logger.error(f"Failed to generate npub: {e}", exc_info=True)
            raise

    def get_nsec(self) -> str:
        """Return the nsec (Bech32 encoded private key)."""
        try:
            priv_hex = self.get_private_key_hex()
            priv_bytes = bytes.fromhex(priv_hex)
            data = convertbits(priv_bytes, 8, 5, True)
            return bech32_encode("nsec", data)
        except Exception as e:
            logger.error(f"Failed to generate nsec: {e}", exc_info=True)
            raise
