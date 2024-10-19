# nostr/encryption_manager.py

import base64
import json
import traceback

from cryptography.fernet import Fernet, InvalidToken

from .logging_config import configure_logging
from .key_manager import KeyManager
from monstr.encrypt import NIP4Encrypt  # Add if used

logger = configure_logging()

class EncryptionManager:
    """
    Handles encryption and decryption of data using Fernet symmetric encryption.
    """

    def __init__(self, key_manager: KeyManager):
        self.key_manager = key_manager
        self.fernet = Fernet(self.key_manager.derive_encryption_key())

    def encrypt_data(self, data: dict) -> bytes:
        """
        Encrypts a dictionary and returns encrypted bytes.

        :param data: The data to encrypt.
        :return: Encrypted data as bytes.
        """
        try:
            json_data = json.dumps(data, indent=4).encode('utf-8')
            encrypted_data = self.fernet.encrypt(json_data)
            logger.debug("Data encrypted successfully.")
            return encrypted_data
        except Exception as e:
            logger.error(f"Failed to encrypt data: {e}")
            logger.error(traceback.format_exc())
            raise

    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """
        Decrypts encrypted bytes and returns the original data.

        :param encrypted_data: The encrypted data to decrypt.
        :return: Decrypted data as bytes.
        """
        try:
            decrypted_data = self.fernet.decrypt(encrypted_data)
            logger.debug("Data decrypted successfully.")
            return decrypted_data
        except InvalidToken:
            logger.error("Invalid encryption key or corrupted data.")
            raise
        except Exception as e:
            logger.error(f"Error decrypting data: {e}")
            logger.error(traceback.format_exc())
            raise
