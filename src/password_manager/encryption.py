# /src/password_manager/encryption.py

import logging
import traceback
import json
import hashlib
import os
import base64
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken
from termcolor import colored
from utils.file_lock import exclusive_lock

# Instantiate the logger
logger = logging.getLogger(__name__)


class EncryptionManager:
    """
    Manages encryption and decryption, handling migration from legacy Fernet
    to modern AES-GCM.
    """

    def __init__(self, encryption_key: bytes, fingerprint_dir: Path):
        """
        Initializes the EncryptionManager with keys for both new (AES-GCM)
        and legacy (Fernet) encryption formats.

        Parameters:
            encryption_key (bytes): A base64-encoded key.
            fingerprint_dir (Path): The directory corresponding to the fingerprint.
        """
        self.fingerprint_dir = fingerprint_dir
        self.parent_seed_file = self.fingerprint_dir / "parent_seed.enc"

        try:
            if isinstance(encryption_key, str):
                encryption_key = encryption_key.encode()

            # (1) Keep both the legacy Fernet instance and the new AES-GCM cipher ready.
            self.key_b64 = encryption_key
            self.fernet = Fernet(self.key_b64)

            self.key = base64.urlsafe_b64decode(self.key_b64)
            self.cipher = AESGCM(self.key)

            logger.debug(f"EncryptionManager initialized for {self.fingerprint_dir}")
        except Exception as e:
            logger.error(
                f"Failed to initialize ciphers with provided encryption key: {e}",
                exc_info=True,
            )
            raise

    def encrypt_data(self, data: bytes) -> bytes:
        """
        (2) Encrypts data using the NEW AES-GCM format, prepending a version
            header and the nonce. All new data will be in this format.
        """
        try:
            nonce = os.urandom(12)  # 96-bit nonce is recommended for AES-GCM
            ciphertext = self.cipher.encrypt(nonce, data, None)
            return b"V2:" + nonce + ciphertext
        except Exception as e:
            logger.error(f"Failed to encrypt data: {e}", exc_info=True)
            raise

    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """
        (3) The core migration logic. Tries the new format first, then falls back
            to the old one. This is the ONLY place decryption logic should live.
        """
        # Try the new V2 format first
        if encrypted_data.startswith(b"V2:"):
            try:
                nonce = encrypted_data[3:15]
                ciphertext = encrypted_data[15:]
                return self.cipher.decrypt(nonce, ciphertext, None)
            except InvalidTag as e:
                logger.error("AES-GCM decryption failed: Invalid authentication tag.")
                raise InvalidToken("AES-GCM decryption failed.") from e

        # If it's not V2, it must be the legacy Fernet format
        else:
            logger.warning("Data is in legacy Fernet format. Attempting migration.")
            try:
                return self.fernet.decrypt(encrypted_data)
            except InvalidToken as e:
                logger.error(
                    "Legacy Fernet decryption failed. Vault may be corrupt or key is incorrect."
                )
                raise InvalidToken(
                    "Could not decrypt data with any available method."
                ) from e

    # --- All functions below this point now use the smart `decrypt_data` method ---

    def encrypt_parent_seed(self, parent_seed: str) -> None:
        """Encrypts and saves the parent seed to 'parent_seed.enc'."""
        data = parent_seed.encode("utf-8")
        encrypted_data = self.encrypt_data(data)  # This now creates V2 format
        with exclusive_lock(self.parent_seed_file) as fh:
            fh.seek(0)
            fh.truncate()
            fh.write(encrypted_data)
        os.chmod(self.parent_seed_file, 0o600)
        logger.info(f"Parent seed encrypted and saved to '{self.parent_seed_file}'.")

    def decrypt_parent_seed(self) -> str:
        """Decrypts and returns the parent seed, handling migration."""
        with exclusive_lock(self.parent_seed_file) as fh:
            fh.seek(0)
            encrypted_data = fh.read()

        is_legacy = not encrypted_data.startswith(b"V2:")
        decrypted_data = self.decrypt_data(encrypted_data)

        if is_legacy:
            logger.info("Parent seed was in legacy format. Re-encrypting to V2 format.")
            self.encrypt_parent_seed(decrypted_data.decode("utf-8").strip())

        return decrypted_data.decode("utf-8").strip()

    def encrypt_and_save_file(self, data: bytes, relative_path: Path) -> None:
        file_path = self.fingerprint_dir / relative_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        encrypted_data = self.encrypt_data(data)
        with exclusive_lock(file_path) as fh:
            fh.seek(0)
            fh.truncate()
            fh.write(encrypted_data)
        os.chmod(file_path, 0o600)

    def decrypt_file(self, relative_path: Path) -> bytes:
        file_path = self.fingerprint_dir / relative_path
        with exclusive_lock(file_path) as fh:
            fh.seek(0)
            encrypted_data = fh.read()
        return self.decrypt_data(encrypted_data)

    def save_json_data(self, data: dict, relative_path: Optional[Path] = None) -> None:
        if relative_path is None:
            relative_path = Path("seedpass_entries_db.json.enc")
        json_data = json.dumps(data, indent=4).encode("utf-8")
        self.encrypt_and_save_file(json_data, relative_path)
        logger.debug(f"JSON data encrypted and saved to '{relative_path}'.")

    def load_json_data(self, relative_path: Optional[Path] = None) -> dict:
        """
        Loads and decrypts JSON data, automatically migrating and re-saving
        if it's in the legacy format.
        """
        if relative_path is None:
            relative_path = Path("seedpass_entries_db.json.enc")

        file_path = self.fingerprint_dir / relative_path
        if not file_path.exists():
            return {"entries": {}}

        with exclusive_lock(file_path) as fh:
            fh.seek(0)
            encrypted_data = fh.read()

        is_legacy = not encrypted_data.startswith(b"V2:")

        try:
            decrypted_data = self.decrypt_data(encrypted_data)
            data = json.loads(decrypted_data.decode("utf-8"))

            # If it was a legacy file, re-save it in the new format now
            if is_legacy:
                logger.info(f"Migrating and re-saving legacy vault file: {file_path}")
                self.save_json_data(data, relative_path)
                self.update_checksum(relative_path)

            return data
        except (InvalidToken, InvalidTag, json.JSONDecodeError) as e:
            logger.error(
                f"FATAL: Could not decrypt or parse data from {file_path}: {e}",
                exc_info=True,
            )
            raise

    def get_encrypted_index(self) -> Optional[bytes]:
        relative_path = Path("seedpass_entries_db.json.enc")
        file_path = self.fingerprint_dir / relative_path
        if not file_path.exists():
            return None
        with exclusive_lock(file_path) as fh:
            fh.seek(0)
            return fh.read()

    def decrypt_and_save_index_from_nostr(
        self, encrypted_data: bytes, relative_path: Optional[Path] = None
    ) -> None:
        """Decrypts data from Nostr and saves it, automatically using the new format."""
        if relative_path is None:
            relative_path = Path("seedpass_entries_db.json.enc")
        try:
            decrypted_data = self.decrypt_data(
                encrypted_data
            )  # This now handles both formats
            data = json.loads(decrypted_data.decode("utf-8"))
            self.save_json_data(data, relative_path)  # This always saves in V2 format
            self.update_checksum(relative_path)
            logger.info("Index file from Nostr was processed and saved successfully.")
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
            raise

    def update_checksum(self, relative_path: Optional[Path] = None) -> None:
        """Updates the checksum file for the specified file."""
        if relative_path is None:
            relative_path = Path("seedpass_entries_db.json.enc")

        file_path = self.fingerprint_dir / relative_path
        if not file_path.exists():
            return

        try:
            with exclusive_lock(file_path) as fh:
                fh.seek(0)
                encrypted_bytes = fh.read()
            checksum = hashlib.sha256(encrypted_bytes).hexdigest()
            checksum_file = file_path.parent / f"{file_path.stem}_checksum.txt"
            with exclusive_lock(checksum_file) as fh:
                fh.seek(0)
                fh.truncate()
                fh.write(checksum.encode("utf-8"))
            os.chmod(checksum_file, 0o600)
        except Exception as e:
            logger.error(
                f"Failed to update checksum for '{relative_path}': {e}", exc_info=True
            )
            raise

    # ... validate_seed and derive_seed_from_mnemonic can remain the same ...
    def validate_seed(self, seed_phrase: str) -> bool:
        try:
            words = seed_phrase.split()
            if len(words) != 12:
                logger.error("Seed phrase does not contain exactly 12 words.")
                print(
                    colored("Error: Seed phrase must contain exactly 12 words.", "red")
                )
                return False
            logger.debug("Seed phrase validated successfully.")
            return True
        except Exception as e:
            logging.error(f"Error validating seed phrase: {e}", exc_info=True)
            print(colored(f"Error: Failed to validate seed phrase: {e}", "red"))
            return False

    def derive_seed_from_mnemonic(self, mnemonic: str, passphrase: str = "") -> bytes:
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
