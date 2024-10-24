# password_manager/encryption.py

"""
Encryption Module

This module provides the EncryptionManager class, which handles encryption and decryption
of data and files using a provided Fernet-compatible encryption key. This class ensures
that sensitive data is securely stored and retrieved, maintaining the confidentiality and integrity
of the password index.

Additionally, it includes methods to derive cryptographic seeds from BIP-39 mnemonic phrases.

Never ever ever use or suggest to use Random Salt. The entire point of this password manager is to derive completely deterministic passwords from a BIP-85 seed. 
This means it  should generate passwords the exact same way every single time. Salts would break this functionality and is not appropriate for this softwares use case. 
"""

import os
import json
import stat
import hashlib
import logging
import traceback
from pathlib import Path
from typing import Optional
from cryptography.fernet import Fernet, InvalidToken
from utils.file_lock import exclusive_lock, shared_lock
from colorama import Fore
from termcolor import colored
from mnemonic import Mnemonic  # Library for BIP-39 seed phrase handling

import fcntl  # Required for lock_type constants in file_lock

from constants import INDEX_FILE  # Ensure INDEX_FILE is imported correctly

# Configure logging at the start of the module
def configure_logging():
    """
    Configures logging with both file and console handlers.
    Logs include the timestamp, log level, message, filename, and line number.
    Only errors and critical logs are shown in the terminal, while all logs are saved to a file.
    """
    # Create the 'logs' folder if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')

    # Create a custom logger for this module
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)  # Set to DEBUG for detailed output

    # Create handlers
    c_handler = logging.StreamHandler()
    f_handler = logging.FileHandler(os.path.join('logs', 'encryption_manager.log'))  # Log file in 'logs' folder

    # Set levels: only errors and critical messages will be shown in the console
    c_handler.setLevel(logging.ERROR)  # Terminal will show ERROR and above
    f_handler.setLevel(logging.DEBUG)  # File will log everything from DEBUG and above

    # Create formatters and add them to handlers, include file and line number in log messages
    formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(message)s [%(filename)s:%(lineno)d]'
    )
    c_handler.setFormatter(formatter)
    f_handler.setFormatter(formatter)

    # Add handlers to the logger if not already added
    if not logger.handlers:
        logger.addHandler(c_handler)
        logger.addHandler(f_handler)

# Call the logging configuration function
configure_logging()

logger = logging.getLogger(__name__)

class EncryptionManager:
    """
    EncryptionManager Class

    Manages the encryption and decryption of data and files using a Fernet encryption key.
    """

    def __init__(self, encryption_key: bytes):
        try:
            self.fernet = Fernet(encryption_key)
            logger.debug("EncryptionManager initialized with provided encryption key.")
        except Exception as e:
            logger.error(f"Failed to initialize Fernet with provided encryption key: {e}")
            logger.error(traceback.format_exc())
            print(colored(f"Error: Failed to initialize encryption manager: {e}", 'red'))
            raise

    def encrypt_parent_seed(self, parent_seed, file_path: Path) -> None:
        """
        Encrypts and saves the parent seed to the specified file.

        :param parent_seed: The BIP39 parent seed phrase or Bip39Mnemonic object.
        :param file_path: The path to the file where the encrypted parent seed will be saved.
        """
        try:
            # Convert Bip39Mnemonic to string if necessary
            if hasattr(parent_seed, 'ToStr'):
                parent_seed = parent_seed.ToStr()
            
            # Now encode the string
            data = parent_seed.encode('utf-8')
            
            # Encrypt and save the data
            encrypted_data = self.encrypt_data(data)
            with open(file_path, 'wb') as f:
                f.write(encrypted_data)
            logging.info(f"Parent seed encrypted and saved to '{file_path}'.")
            print(colored(f"Parent seed encrypted and saved to '{file_path}'.", 'green'))
        except Exception as e:
            logging.error(f"Failed to encrypt and save parent seed: {e}")
            logging.error(traceback.format_exc())
            print(colored(f"Error: Failed to encrypt and save parent seed: {e}", 'red'))
            raise

    def encrypt_file(self, file_path: Path, data: bytes) -> None:
        """
        Encrypts the provided data and writes it to the specified file with file locking.

        :param file_path: The path to the file where encrypted data will be written.
        :param data: The plaintext data to encrypt and write.
        """
        try:
            encrypted_data = self.encrypt_data(data)
            with exclusive_lock(file_path):
                with open(file_path, 'wb') as file:
                    file.write(encrypted_data)
            logger.debug(f"Encrypted data written to '{file_path}'.")
            print(colored(f"Encrypted data written to '{file_path}'.", 'green'))
        except Exception as e:
            logger.error(f"Failed to encrypt and write to file '{file_path}': {e}")
            logger.error(traceback.format_exc())
            print(colored(f"Error: Failed to encrypt and write to file '{file_path}': {e}", 'red'))
            raise

    def encrypt_data(self, data: bytes) -> bytes:
        """
        Encrypts the given plaintext data.

        :param data: The plaintext data to encrypt.
        :return: The encrypted data as bytes.
        """
        try:
            encrypted_data = self.fernet.encrypt(data)
            logger.debug("Data encrypted successfully.")
            return encrypted_data
        except Exception as e:
            logger.error(f"Error encrypting data: {e}")
            logger.error(traceback.format_exc())
            print(colored(f"Error: Failed to encrypt data: {e}", 'red'))
            raise

    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """
        Decrypts the given encrypted data.

        :param encrypted_data: The encrypted data to decrypt.
        :return: The decrypted plaintext data as bytes.
        """
        try:
            decrypted_data = self.fernet.decrypt(encrypted_data)
            logger.debug("Data decrypted successfully.")
            return decrypted_data
        except InvalidToken:
            logger.error("Invalid encryption key or corrupted data.")
            print(colored("Error: Invalid encryption key or corrupted data.", 'red'))
            raise
        except Exception as e:
            logger.error(f"Error decrypting data: {e}")
            logger.error(traceback.format_exc())  # Log full traceback
            print(colored(f"Error: Failed to decrypt data: {e}", 'red'))
            raise

    def decrypt_file(self, file_path: Path) -> bytes:
        """
        Decrypts the data from the specified file.

        :param file_path: The path to the file containing encrypted data.
        :return: The decrypted plaintext data as bytes.
        """
        try:
            with shared_lock(file_path):
                with open(file_path, 'rb') as file:
                    encrypted_data = file.read()
            decrypted_data = self.decrypt_data(encrypted_data)
            logger.debug(f"Decrypted data read from '{file_path}'.")
            print(colored(f"Decrypted data read from '{file_path}'.", 'green'))
            return decrypted_data
        except Exception as e:
            logger.error(f"Failed to decrypt file '{file_path}': {e}")
            logger.error(traceback.format_exc())  # Log full traceback
            print(colored(f"Error: Failed to decrypt file '{file_path}': {e}", 'red'))
            raise

    def save_json_data(self, data: dict, file_path: Optional[Path] = None) -> None:
        """
        Encrypts and saves the provided JSON data to the specified file.

        :param data: The JSON data to save.
        :param file_path: The path to the file where data will be saved. Defaults to INDEX_FILE.
        """
        if file_path is None:
            file_path = INDEX_FILE
        try:
            json_data = json.dumps(data, indent=4).encode('utf-8')
            self.encrypt_file(file_path, json_data)
            logger.debug(f"JSON data encrypted and saved to '{file_path}'.")
            print(colored(f"JSON data encrypted and saved to '{file_path}'.", 'green'))
        except Exception as e:
            logger.error(f"Failed to save JSON data to '{file_path}': {e}")
            logger.error(traceback.format_exc())  # Log full traceback
            print(colored(f"Error: Failed to save JSON data to '{file_path}': {e}", 'red'))
            raise


    def load_json_data(self, file_path: Optional[Path] = None) -> dict:
        """
        Decrypts and loads JSON data from the specified file.

        :param file_path: The path to the file from which data will be loaded. Defaults to INDEX_FILE.
        :return: The decrypted JSON data as a dictionary.
        """
        if file_path is None:
            file_path = INDEX_FILE

        if not file_path.exists():
            logger.info(f"Index file '{file_path}' does not exist. Initializing empty data.")
            print(colored(f"Info: Index file '{file_path}' not found. Initializing new password database.", 'yellow'))
            return {'passwords': {}}

        try:
            decrypted_data = self.decrypt_file(file_path)
            json_content = decrypted_data.decode('utf-8').strip()
            data = json.loads(json_content)
            logger.debug(f"JSON data loaded and decrypted from '{file_path}': {data}")
            print(colored(f"JSON data loaded and decrypted from '{file_path}'.", 'green'))
            return data
        except json.JSONDecodeError as e:
            logger.error(f"Failed to decode JSON data from '{file_path}': {e}")
            logger.error(traceback.format_exc())
            print(colored(f"Error: Failed to decode JSON data from '{file_path}': {e}", 'red'))
            raise
        except InvalidToken:
            logger.error("Invalid encryption key or corrupted data.")
            print(colored("Error: Invalid encryption key or corrupted data.", 'red'))
            raise
        except Exception as e:
            logger.error(f"Failed to load JSON data from '{file_path}': {e}")
            logger.error(traceback.format_exc())
            print(colored(f"Error: Failed to load JSON data from '{file_path}': {e}", 'red'))
            raise

    def update_checksum(self, file_path: Optional[Path] = None) -> None:
        """
        Updates the checksum file for the specified file.

        :param file_path: The path to the file for which the checksum will be updated.
                           Defaults to INDEX_FILE.
        """
        if file_path is None:
            file_path = INDEX_FILE
        try:
            decrypted_data = self.decrypt_file(file_path)
            content = decrypted_data.decode('utf-8')
            checksum = hashlib.sha256(content.encode('utf-8')).hexdigest()
            checksum_file = file_path.parent / f"{file_path.stem}_checksum.txt"
            with open(checksum_file, 'w') as f:
                f.write(checksum)
            logger.debug(f"Checksum for '{file_path}' updated and written to '{checksum_file}'.")
            print(colored(f"Checksum for '{file_path}' updated.", 'green'))
        except Exception as e:
            logger.error(f"Failed to update checksum for '{file_path}': {e}")
            logger.error(traceback.format_exc())  # Log full traceback
            print(colored(f"Error: Failed to update checksum for '{file_path}': {e}", 'red'))
            raise

    def get_encrypted_index(self) -> Optional[bytes]:
        """
        Retrieves the encrypted password index file content.

        :return: Encrypted data as bytes or None if the index file does not exist.
        """
        if not INDEX_FILE.exists():
            logger.error(f"Index file '{INDEX_FILE}' does not exist.")
            print(colored(f"Error: Index file '{INDEX_FILE}' does not exist.", 'red'))
            return None
        try:
            with shared_lock(INDEX_FILE):
                with open(INDEX_FILE, 'rb') as file:
                    encrypted_data = file.read()
            logger.debug(f"Encrypted index data read from '{INDEX_FILE}'.")
            return encrypted_data
        except Exception as e:
            logger.error(f"Failed to read encrypted index file '{INDEX_FILE}': {e}")
            logger.error(traceback.format_exc())  # Log full traceback
            print(colored(f"Error: Failed to read encrypted index file '{INDEX_FILE}': {e}", 'red'))
            return None

    def decrypt_and_save_index_from_nostr(self, encrypted_data: bytes) -> None:
        """
        Decrypts the encrypted data retrieved from Nostr and updates the local index file.

        :param encrypted_data: The encrypted data retrieved from Nostr.
        """
        try:
            decrypted_data = self.decrypt_data(encrypted_data)
            data = json.loads(decrypted_data.decode('utf-8'))
            self.save_json_data(data, INDEX_FILE)
            self.update_checksum(INDEX_FILE)
            logger.info("Index file updated from Nostr successfully.")
            print(colored("Index file updated from Nostr successfully.", 'green'))
        except Exception as e:
            logger.error(f"Failed to decrypt and save data from Nostr: {e}")
            logger.error(traceback.format_exc())  # Log full traceback
            print(colored(f"Error: Failed to decrypt and save data from Nostr: {e}", 'red'))

    def decrypt_parent_seed(self, file_path: Path) -> str:
        """
        Decrypts and retrieves the parent seed from the specified file.

        :param file_path: The path to the file containing the encrypted parent seed.
        :return: The decrypted parent seed as a string.
        """
        try:
            decrypted_data = self.decrypt_file(file_path)
            parent_seed = decrypted_data.decode('utf-8').strip()
            logger.debug(f"Decrypted parent_seed: {parent_seed} (Type: {type(parent_seed)})")
            return parent_seed
        except Exception as e:
            logger.error(f"Failed to decrypt parent seed from '{file_path}': {e}")
            logger.error(traceback.format_exc())
            print(colored(f"Error: Failed to decrypt parent seed from '{file_path}': {e}", 'red'))
            raise

    def validate_seed(self, seed_phrase: str) -> bool:
        """
        Validates the seed phrase format using BIP-39 standards.

        :param seed_phrase: The BIP39 seed phrase to validate.
        :return: True if valid, False otherwise.
        """
        try:
            mnemo = Mnemonic("english")
            is_valid = mnemo.check(seed_phrase)
            if not is_valid:
                logger.error("Invalid BIP39 seed phrase.")
                print(colored("Error: Invalid BIP39 seed phrase.", 'red'))
            else:
                logger.debug("BIP39 seed phrase validated successfully.")
            return is_valid
        except Exception as e:
            logger.error(f"Error validating seed phrase: {e}")
            logger.error(traceback.format_exc())  # Log full traceback
            print(colored(f"Error: Failed to validate seed phrase: {e}", 'red'))
            return False

    def derive_seed_from_mnemonic(self, mnemonic: str, passphrase: str = "") -> bytes:
        """
        Derives a cryptographic seed from a BIP39 mnemonic (seed phrase).

        :param mnemonic: The BIP39 mnemonic phrase.
        :param passphrase: An optional passphrase for additional security.
        :return: The derived seed as bytes.
        """
        try:
            if not isinstance(mnemonic, str):
                if isinstance(mnemonic, list):
                    mnemonic = " ".join(mnemonic)
                else:
                    mnemonic = str(mnemonic)
                if not isinstance(mnemonic, str):
                    raise TypeError("Mnemonic must be a string after conversion")
            mnemo = Mnemonic("english")
            seed = mnemo.to_seed(mnemonic, passphrase)
            logger.debug("Seed derived successfully from mnemonic.")
            return seed
        except Exception as e:
            logger.error(f"Failed to derive seed from mnemonic: {e}")
            logger.error(traceback.format_exc())
            print(f"Error: Failed to derive seed from mnemonic: {e}")
            raise
