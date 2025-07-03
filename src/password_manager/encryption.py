# password_manager/encryption.py

"""
Encryption Module

This module provides the EncryptionManager class, which handles encryption and decryption
of data and files using a provided Fernet-compatible encryption key. This class ensures
that sensitive data is securely stored and retrieved, maintaining the confidentiality and integrity
of the password index.

Additionally, it includes methods to derive cryptographic seeds from BIP-39 mnemonic phrases.

Never ever ever use or suggest to use Random Salt. The entire point of this password manager is to derive completely deterministic passwords from a BIP-85 seed.
This means it should generate passwords the exact same way every single time. Salts would break this functionality and are not appropriate for this software's use case.
"""

import logging
import traceback
import json
import hashlib
import os
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from termcolor import colored
from utils.file_lock import (
    exclusive_lock,
)  # Ensure this utility is correctly implemented

# Instantiate the logger
logger = logging.getLogger(__name__)


class EncryptionManager:
    """
    EncryptionManager Class

    Manages the encryption and decryption of data and files using a Fernet encryption key.
    """

    def __init__(self, encryption_key: bytes, fingerprint_dir: Path):
        """
        Initializes the EncryptionManager with the provided encryption key and fingerprint directory.

        Parameters:
            encryption_key (bytes): The Fernet encryption key.
            fingerprint_dir (Path): The directory corresponding to the fingerprint.
        """
        self.fingerprint_dir = fingerprint_dir
        self.parent_seed_file = self.fingerprint_dir / "parent_seed.enc"
        self.key = encryption_key

        try:
            self.fernet = Fernet(self.key)
            logger.debug(f"EncryptionManager initialized for {self.fingerprint_dir}")
        except Exception as e:
            logger.error(
                f"Failed to initialize Fernet with provided encryption key: {e}"
            )
            print(
                colored(f"Error: Failed to initialize encryption manager: {e}", "red")
            )
            raise

    def encrypt_parent_seed(self, parent_seed: str) -> None:
        """
        Encrypts and saves the parent seed to 'parent_seed.enc' within the fingerprint directory.

        :param parent_seed: The BIP39 parent seed phrase.
        """
        try:
            # Convert seed to bytes
            data = parent_seed.encode("utf-8")

            # Encrypt the data
            encrypted_data = self.encrypt_data(data)

            # Write the encrypted data to the file with locking
            with exclusive_lock(self.parent_seed_file):
                with open(self.parent_seed_file, "wb") as f:
                    f.write(encrypted_data)

            # Set file permissions to read/write for the user only
            os.chmod(self.parent_seed_file, 0o600)

            logger.info(
                f"Parent seed encrypted and saved to '{self.parent_seed_file}'."
            )
            print(
                colored(
                    f"Parent seed encrypted and saved to '{self.parent_seed_file}'.",
                    "green",
                )
            )
        except Exception as e:
            logger.error(f"Failed to encrypt and save parent seed: {e}", exc_info=True)
            print(colored(f"Error: Failed to encrypt and save parent seed: {e}", "red"))
            raise

    def decrypt_parent_seed(self) -> str:
        """
        Decrypts and returns the parent seed from 'parent_seed.enc' within the fingerprint directory.

        :return: The decrypted parent seed.
        """
        try:
            parent_seed_path = self.fingerprint_dir / "parent_seed.enc"
            with exclusive_lock(parent_seed_path):
                with open(parent_seed_path, "rb") as f:
                    encrypted_data = f.read()

            decrypted_data = self.decrypt_data(encrypted_data)
            parent_seed = decrypted_data.decode("utf-8").strip()

            logger.debug(
                f"Parent seed decrypted successfully from '{parent_seed_path}'."
            )
            return parent_seed
        except InvalidToken:
            logger.error(
                "Invalid encryption key or corrupted data while decrypting parent seed."
            )
            raise
        except Exception as e:
            logger.error(f"Failed to decrypt parent seed: {e}", exc_info=True)
            print(colored(f"Error: Failed to decrypt parent seed: {e}", "red"))
            raise

    def encrypt_data(self, data: bytes) -> bytes:
        """
        Encrypts the given data using Fernet.

        :param data: Data to encrypt.
        :return: Encrypted data.
        """
        try:
            encrypted_data = self.fernet.encrypt(data)
            logger.debug("Data encrypted successfully.")
            return encrypted_data
        except Exception as e:
            logger.error(f"Failed to encrypt data: {e}", exc_info=True)
            print(colored(f"Error: Failed to encrypt data: {e}", "red"))
            raise

    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """
        Decrypts the provided encrypted data using the derived key.

        :param encrypted_data: The encrypted data to decrypt.
        :return: The decrypted data as bytes.
        """
        try:
            decrypted_data = self.fernet.decrypt(encrypted_data)
            logger.debug("Data decrypted successfully.")
            return decrypted_data
        except InvalidToken:
            logger.error(
                "Invalid encryption key or corrupted data while decrypting data."
            )
            raise
        except Exception as e:
            logger.error(f"Failed to decrypt data: {e}", exc_info=True)
            print(colored(f"Error: Failed to decrypt data: {e}", "red"))
            raise

    def encrypt_and_save_file(self, data: bytes, relative_path: Path) -> None:
        """
        Encrypts data and saves it to a specified relative path within the fingerprint directory.

        :param data: Data to encrypt.
        :param relative_path: Relative path within the fingerprint directory to save the encrypted data.
        """
        try:
            # Define the full path
            file_path = self.fingerprint_dir / relative_path

            # Ensure the parent directories exist
            file_path.parent.mkdir(parents=True, exist_ok=True)

            # Encrypt the data
            encrypted_data = self.encrypt_data(data)

            # Write the encrypted data to the file with locking
            with exclusive_lock(file_path):
                with open(file_path, "wb") as f:
                    f.write(encrypted_data)

            # Set file permissions to read/write for the user only
            os.chmod(file_path, 0o600)

            logger.info(f"Data encrypted and saved to '{file_path}'.")
            print(colored(f"Data encrypted and saved to '{file_path}'.", "green"))
        except Exception as e:
            logger.error(
                f"Failed to encrypt and save data to '{relative_path}': {e}",
                exc_info=True,
            )
            print(
                colored(
                    f"Error: Failed to encrypt and save data to '{relative_path}': {e}",
                    "red",
                )
            )
            raise

    def decrypt_file(self, relative_path: Path) -> bytes:
        """
        Decrypts data from a specified relative path within the fingerprint directory.

        :param relative_path: Relative path within the fingerprint directory to decrypt the data from.
        :return: Decrypted data as bytes.
        """
        try:
            # Define the full path
            file_path = self.fingerprint_dir / relative_path

            # Read the encrypted data with locking
            with exclusive_lock(file_path):
                with open(file_path, "rb") as f:
                    encrypted_data = f.read()

            # Decrypt the data
            decrypted_data = self.decrypt_data(encrypted_data)
            logger.debug(f"Data decrypted successfully from '{file_path}'.")
            return decrypted_data
        except InvalidToken:
            logger.error(
                "Invalid encryption key or corrupted data while decrypting file."
            )
            raise
        except Exception as e:
            logger.error(
                f"Failed to decrypt data from '{relative_path}': {e}", exc_info=True
            )
            print(
                colored(
                    f"Error: Failed to decrypt data from '{relative_path}': {e}", "red"
                )
            )
            raise

    def save_json_data(self, data: dict, relative_path: Optional[Path] = None) -> None:
        """
        Encrypts and saves the provided JSON data to the specified relative path within the fingerprint directory.

        :param data: The JSON data to save.
        :param relative_path: The relative path within the fingerprint directory where data will be saved.
                              Defaults to 'seedpass_passwords_db.json.enc'.
        """
        if relative_path is None:
            relative_path = Path("seedpass_passwords_db.json.enc")
        try:
            json_data = json.dumps(data, indent=4).encode("utf-8")
            self.encrypt_and_save_file(json_data, relative_path)
            logger.debug(f"JSON data encrypted and saved to '{relative_path}'.")
            print(
                colored(f"JSON data encrypted and saved to '{relative_path}'.", "green")
            )
        except Exception as e:
            logger.error(
                f"Failed to save JSON data to '{relative_path}': {e}", exc_info=True
            )
            print(
                colored(
                    f"Error: Failed to save JSON data to '{relative_path}': {e}", "red"
                )
            )
            raise

    def load_json_data(self, relative_path: Optional[Path] = None) -> dict:
        """
        Decrypts and loads JSON data from the specified relative path within the fingerprint directory.

        :param relative_path: The relative path within the fingerprint directory from which data will be loaded.
                              Defaults to 'seedpass_passwords_db.json.enc'.
        :return: The decrypted JSON data as a dictionary.
        """
        if relative_path is None:
            relative_path = Path("seedpass_passwords_db.json.enc")

        file_path = self.fingerprint_dir / relative_path

        if not file_path.exists():
            logger.info(
                f"Index file '{file_path}' does not exist. Initializing empty data."
            )
            print(
                colored(
                    f"Info: Index file '{file_path}' not found. Initializing new password database.",
                    "yellow",
                )
            )
            return {"entries": {}}

        try:
            decrypted_data = self.decrypt_file(relative_path)
            json_content = decrypted_data.decode("utf-8").strip()
            data = json.loads(json_content)
            logger.debug(f"JSON data loaded and decrypted from '{file_path}': {data}")
            return data
        except json.JSONDecodeError as e:
            logger.error(
                f"Failed to decode JSON data from '{file_path}': {e}", exc_info=True
            )
            raise
        except InvalidToken:
            logger.error(
                "Invalid encryption key or corrupted data while decrypting JSON data."
            )
            raise
        except Exception as e:
            logger.error(
                f"Failed to load JSON data from '{file_path}': {e}", exc_info=True
            )
            raise

    def update_checksum(self, relative_path: Optional[Path] = None) -> None:
        """
        Updates the checksum file for the specified file within the fingerprint directory.

        :param relative_path: The relative path within the fingerprint directory for which the checksum will be updated.
                              Defaults to 'seedpass_passwords_db.json.enc'.
        """
        if relative_path is None:
            relative_path = Path("seedpass_passwords_db.json.enc")
        try:
            file_path = self.fingerprint_dir / relative_path
            logger.debug("Calculating checksum of the encrypted file bytes.")

            with exclusive_lock(file_path):
                with open(file_path, "rb") as f:
                    encrypted_bytes = f.read()

            checksum = hashlib.sha256(encrypted_bytes).hexdigest()
            logger.debug(f"New checksum: {checksum}")

            checksum_file = file_path.parent / f"{file_path.stem}_checksum.txt"

            # Write the checksum to the file with locking
            with exclusive_lock(checksum_file):
                with open(checksum_file, "w") as f:
                    f.write(checksum)

            # Set file permissions to read/write for the user only
            os.chmod(checksum_file, 0o600)

            logger.debug(
                f"Checksum for '{file_path}' updated and written to '{checksum_file}'."
            )
            print(colored(f"Checksum for '{file_path}' updated.", "green"))
        except Exception as e:
            logger.error(
                f"Failed to update checksum for '{relative_path}': {e}", exc_info=True
            )
            print(
                colored(
                    f"Error: Failed to update checksum for '{relative_path}': {e}",
                    "red",
                )
            )
            raise

    def get_encrypted_index(self) -> Optional[bytes]:
        """
        Retrieves the encrypted password index file content.

        :return: Encrypted data as bytes or None if the index file does not exist.
        """
        try:
            relative_path = Path("seedpass_passwords_db.json.enc")
            if not (self.fingerprint_dir / relative_path).exists():
                logger.error(
                    f"Index file '{relative_path}' does not exist in '{self.fingerprint_dir}'."
                )
                print(
                    colored(
                        f"Error: Index file '{relative_path}' does not exist.", "red"
                    )
                )
                return None

            with exclusive_lock(self.fingerprint_dir / relative_path):
                with open(self.fingerprint_dir / relative_path, "rb") as file:
                    encrypted_data = file.read()

            logger.debug(f"Encrypted index data read from '{relative_path}'.")
            return encrypted_data
        except Exception as e:
            logger.error(
                f"Failed to read encrypted index file '{relative_path}': {e}",
                exc_info=True,
            )
            print(
                colored(
                    f"Error: Failed to read encrypted index file '{relative_path}': {e}",
                    "red",
                )
            )
            return None

    def decrypt_and_save_index_from_nostr(
        self, encrypted_data: bytes, relative_path: Optional[Path] = None
    ) -> None:
        """
        Decrypts the encrypted data retrieved from Nostr and updates the local index file.

        :param encrypted_data: The encrypted data retrieved from Nostr.
        :param relative_path: The relative path within the fingerprint directory to update.
                              Defaults to 'seedpass_passwords_db.json.enc'.
        """
        if relative_path is None:
            relative_path = Path("seedpass_passwords_db.json.enc")
        try:
            decrypted_data = self.decrypt_data(encrypted_data)
            data = json.loads(decrypted_data.decode("utf-8"))
            self.save_json_data(data, relative_path)
            self.update_checksum(relative_path)
            logger.info("Index file updated from Nostr successfully.")
            print(colored("Index file updated from Nostr successfully.", "green"))
        except Exception as e:
            logger.error(
                f"Failed to decrypt and save data from Nostr: {e}", exc_info=True
            )
            print(
                colored(
                    f"Error: Failed to decrypt and save data from Nostr: {e}", "red"
                )
            )
            # Re-raise the exception to inform the calling function of the failure
            raise

    def validate_seed(self, seed_phrase: str) -> bool:
        """
        Validates the seed phrase format using BIP-39 standards.

        :param seed_phrase: The BIP39 seed phrase to validate.
        :return: True if valid, False otherwise.
        """
        try:
            words = seed_phrase.split()
            if len(words) != 12:
                logger.error("Seed phrase does not contain exactly 12 words.")
                print(
                    colored("Error: Seed phrase must contain exactly 12 words.", "red")
                )
                return False
            # Additional validation can be added here (e.g., word list checks)
            logger.debug("Seed phrase validated successfully.")
            return True
        except Exception as e:
            logging.error(f"Error validating seed phrase: {e}", exc_info=True)
            print(colored(f"Error: Failed to validate seed phrase: {e}", "red"))
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
            from bip_utils import Bip39SeedGenerator

            seed = Bip39SeedGenerator(mnemonic).Generate(passphrase)
            logger.debug("Seed derived successfully from mnemonic.")
            return seed
        except Exception as e:
            logger.error(f"Failed to derive seed from mnemonic: {e}", exc_info=True)
            print(colored(f"Error: Failed to derive seed from mnemonic: {e}", "red"))
            raise
