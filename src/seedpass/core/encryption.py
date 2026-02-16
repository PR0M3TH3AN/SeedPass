# /src/seedpass.core/encryption.py

import logging
import traceback

try:
    import orjson as json_lib  # type: ignore

    JSONDecodeError = orjson.JSONDecodeError
    USE_ORJSON = True
except Exception:  # pragma: no cover - fallback for environments without orjson
    import json as json_lib
    from json import JSONDecodeError

    USE_ORJSON = False
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


def get_salt_from_parent_seed_file(file_path: Path) -> bytes:
    """
    Reads the salt from the parent seed file if it exists and uses the V3 format.

    Parameters:
        file_path (Path): The path to the parent seed file.

    Returns:
        bytes: The 16-byte salt if found, otherwise an empty bytes object.
    """
    if not file_path.exists():
        return b""
    try:
        with open(file_path, "rb") as f:
            header = f.read(3)
            if header == b"V3:":
                return f.read(16)
    except Exception as e:
        logger.warning(f"Failed to read salt from {file_path}: {e}")
    return b""


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
                if len(ciphertext) < 16:
                    logger.error("AES-GCM payload too short")
                    raise InvalidToken("AES-GCM payload too short")
                return self.cipher.decrypt(nonce, ciphertext, None)
            except InvalidTag as e:
                logger.error("AES-GCM decryption failed: Invalid authentication tag.")
                try:
                    result = self.fernet.decrypt(encrypted_data[3:])
                    logger.warning(
                        "Legacy-format file had incorrect 'V2:' header; decrypted with Fernet"
                    )
                    return result
                except InvalidToken:
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

    def encrypt_parent_seed(self, parent_seed: str, salt: bytes = b"") -> None:
        """Encrypts and saves the parent seed to 'parent_seed.enc'."""
        data = parent_seed.encode("utf-8")

        if salt:
            # V3 format: V3:<salt(16)><nonce(12)><ciphertext>
            try:
                nonce = os.urandom(12)
                ciphertext = self.cipher.encrypt(nonce, data, None)
                encrypted_data = b"V3:" + salt + nonce + ciphertext
            except Exception as e:
                logger.error(f"Failed to encrypt parent seed with V3 format: {e}", exc_info=True)
                raise
        else:
            # Fallback to V2 (no salt stored) or use encrypt_data
            encrypted_data = self.encrypt_data(data)  # This creates V2 format

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

        if encrypted_data.startswith(b"V3:"):
            # V3 format: V3:<salt(16)><nonce(12)><ciphertext>
            try:
                # Salt is used for key derivation externally, so we skip it here
                nonce = encrypted_data[19:31]
                ciphertext = encrypted_data[31:]
                if len(ciphertext) < 16:
                    raise InvalidToken("AES-GCM payload too short")
                decrypted_data = self.cipher.decrypt(nonce, ciphertext, None)
                return decrypted_data.decode("utf-8").strip()
            except InvalidTag as e:
                logger.error("AES-GCM decryption failed for V3 parent seed.")
                raise InvalidToken("AES-GCM decryption failed.") from e

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
            fh.flush()
            os.fsync(fh.fileno())
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
        if USE_ORJSON:
            json_data = json_lib.dumps(data)
        else:
            json_data = json_lib.dumps(data, separators=(",", ":")).encode("utf-8")
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
            if USE_ORJSON:
                data = json_lib.loads(decrypted_data)
            else:
                data = json_lib.loads(decrypted_data.decode("utf-8"))

            # If it was a legacy file, re-save it in the new format now
            if is_legacy:
                logger.info(f"Migrating and re-saving legacy vault file: {file_path}")
                self.save_json_data(data, relative_path)
                self.update_checksum(relative_path)

            return data
        except (InvalidToken, InvalidTag, JSONDecodeError) as e:
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
        self,
        encrypted_data: bytes,
        relative_path: Optional[Path] = None,
        *,
        strict: bool = True,
        merge: bool = False,
    ) -> bool:
        """Decrypts data from Nostr and saves it.

        Parameters
        ----------
        encrypted_data:
            The payload downloaded from Nostr.
        relative_path:
            Destination filename under the profile directory.
        strict:
            When ``True`` (default) re-raise any decryption error. When ``False``
            return ``False`` if decryption fails.
        """
        if relative_path is None:
            relative_path = Path("seedpass_entries_db.json.enc")
        try:
            decrypted_data = self.decrypt_data(encrypted_data)
            if USE_ORJSON:
                data = json_lib.loads(decrypted_data)
            else:
                data = json_lib.loads(decrypted_data.decode("utf-8"))
            if merge and (self.fingerprint_dir / relative_path).exists():
                current = self.load_json_data(relative_path)
                current_entries = current.get("entries", {})
                for idx, entry in data.get("entries", {}).items():
                    cur_ts = current_entries.get(idx, {}).get("modified_ts", 0)
                    new_ts = entry.get("modified_ts", 0)
                    if idx not in current_entries or new_ts >= cur_ts:
                        current_entries[idx] = entry
                current["entries"] = current_entries
                if "schema_version" in data:
                    current["schema_version"] = max(
                        current.get("schema_version", 0), data.get("schema_version", 0)
                    )
                data = current
            self.save_json_data(data, relative_path)  # This always saves in V2 format
            self.update_checksum(relative_path)
            logger.info("Index file from Nostr was processed and saved successfully.")
            print(colored("Index file updated from Nostr successfully.", "green"))
            return True
        except Exception as e:  # pragma: no cover - error handling
            if strict:
                logger.error(
                    f"Failed to decrypt and save data from Nostr: {e}",
                    exc_info=True,
                )
                print(
                    colored(
                        f"Error: Failed to decrypt and save data from Nostr: {e}",
                        "red",
                    )
                )
                raise
            logger.warning(f"Failed to decrypt index from Nostr: {e}")
            return False

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
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(checksum_file, 0o600)
        except Exception as e:
            logger.error(
                f"Failed to update checksum for '{relative_path}': {e}",
                exc_info=True,
            )
            raise

    # ... validate_seed and derive_seed_from_mnemonic can remain the same ...
    def validate_seed(self, seed_phrase: str) -> bool:
        try:
            words = seed_phrase.split()
            if len(words) != 12:
                logger.error("Seed phrase does not contain exactly 12 words.")
                print(
                    colored(
                        "Error: Seed phrase must contain exactly 12 words.",
                        "red",
                    )
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
