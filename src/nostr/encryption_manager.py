# nostr/encryption_manager.py

import base64
import logging
import traceback
from cryptography.fernet import Fernet, InvalidToken

from .key_manager import KeyManager

# Instantiate the logger
logger = logging.getLogger(__name__)

class EncryptionManager:
    """
    Manages encryption and decryption using Fernet symmetric encryption.
    """
    
    def __init__(self, key_manager: KeyManager):
        """
        Initializes the EncryptionManager with a Fernet instance.

        :param key_manager: An instance of KeyManager to derive the encryption key.
        """
        try:
            # Derive the raw encryption key (32 bytes)
            raw_key = key_manager.derive_encryption_key()
            logger.debug(f"Derived raw encryption key length: {len(raw_key)} bytes")
            
            # Ensure the raw key is exactly 32 bytes
            if len(raw_key) != 32:
                raise ValueError(f"Derived key length is {len(raw_key)} bytes; expected 32 bytes.")
            
            # Base64-encode the raw key to make it URL-safe
            b64_key = base64.urlsafe_b64encode(raw_key)
            logger.debug(f"Base64-encoded encryption key length: {len(b64_key)} bytes")
            
            # Initialize Fernet with the base64-encoded key
            self.fernet = Fernet(b64_key)
            logger.info("Fernet encryption manager initialized successfully.")
        
        except Exception as e:
            logger.error(f"EncryptionManager initialization failed: {e}")
            logger.error(traceback.format_exc())
            raise
    
    def encrypt_parent_seed(self, seed: str, file_path: str) -> None:
        """
        Encrypts the parent seed and saves it to the specified file.

        :param seed: The BIP-39 seed phrase as a string.
        :param file_path: The file path to save the encrypted seed.
        """
        try:
            encrypted_seed = self.fernet.encrypt(seed.encode('utf-8'))
            with open(file_path, 'wb') as f:
                f.write(encrypted_seed)
            logger.debug(f"Parent seed encrypted and saved to '{file_path}'.")
        except Exception as e:
            logger.error(f"Failed to encrypt and save parent seed: {e}")
            logger.error(traceback.format_exc())
            raise
    
    def decrypt_parent_seed(self, file_path: str) -> str:
        """
        Decrypts the parent seed from the specified file.

        :param file_path: The file path to read the encrypted seed.
        :return: The decrypted parent seed as a string.
        """
        try:
            with open(file_path, 'rb') as f:
                encrypted_seed = f.read()
            decrypted_seed = self.fernet.decrypt(encrypted_seed).decode('utf-8')
            logger.debug(f"Parent seed decrypted successfully from '{file_path}'.")
            return decrypted_seed
        except InvalidToken:
            logger.error("Decryption failed: Invalid token. Possibly incorrect password or corrupted file.")
            raise ValueError("Decryption failed: Invalid token. Possibly incorrect password or corrupted file.")
        except Exception as e:
            logger.error(f"Failed to decrypt parent seed: {e}")
            logger.error(traceback.format_exc())
            raise
    
    def encrypt_data(self, data: dict) -> bytes:
        """
        Encrypts a dictionary by serializing it to JSON and then encrypting it.

        :param data: The dictionary to encrypt.
        :return: Encrypted data as bytes.
        """
        try:
            json_data = json.dumps(data).encode('utf-8')
            encrypted = self.fernet.encrypt(json_data)
            logger.debug("Data encrypted successfully.")
            return encrypted
        except Exception as e:
            logger.error(f"Data encryption failed: {e}")
            logger.error(traceback.format_exc())
            raise
    
    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """
        Decrypts encrypted data.

        :param encrypted_data: The encrypted data as bytes.
        :return: Decrypted data as bytes.
        """
        try:
            decrypted = self.fernet.decrypt(encrypted_data)
            logger.debug("Data decrypted successfully.")
            return decrypted
        except InvalidToken as e:
            logger.error(f"Decryption failed: Invalid token. {e}")
            logger.error(traceback.format_exc())
            raise
        except Exception as e:
            logger.error(f"Data decryption failed: {e}")
            logger.error(traceback.format_exc())
            raise
