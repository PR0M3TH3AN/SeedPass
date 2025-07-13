"""Vault utilities for reading and writing encrypted files."""

from pathlib import Path
from typing import Optional, Union
from os import PathLike

from .encryption import EncryptionManager


class Vault:
    """Simple wrapper around :class:`EncryptionManager` for vault storage."""

    INDEX_FILENAME = "seedpass_entries_db.json.enc"
    CONFIG_FILENAME = "seedpass_config.json.enc"

    def __init__(
        self,
        encryption_manager: EncryptionManager,
        fingerprint_dir: Union[str, PathLike[str], Path],
    ):
        self.encryption_manager = encryption_manager
        self.fingerprint_dir = Path(fingerprint_dir)
        self.index_file = self.fingerprint_dir / self.INDEX_FILENAME
        self.config_file = self.fingerprint_dir / self.CONFIG_FILENAME

    def set_encryption_manager(self, manager: EncryptionManager) -> None:
        """Replace the internal encryption manager."""
        self.encryption_manager = manager

    # ----- Password index helpers -----
    def load_index(self) -> dict:
        """Return decrypted password index data as a dict, applying migrations."""
        legacy_file = self.fingerprint_dir / "seedpass_passwords_db.json.enc"
        if legacy_file.exists() and not self.index_file.exists():
            legacy_checksum = (
                self.fingerprint_dir / "seedpass_passwords_db_checksum.txt"
            )
            legacy_file.rename(self.index_file)
            if legacy_checksum.exists():
                legacy_checksum.rename(
                    self.fingerprint_dir / "seedpass_entries_db_checksum.txt"
                )

        data = self.encryption_manager.load_json_data(self.index_file)
        from .migrations import apply_migrations, LATEST_VERSION

        version = data.get("schema_version", 0)
        if version > LATEST_VERSION:
            raise ValueError(
                f"File schema version {version} is newer than supported {LATEST_VERSION}"
            )
        data = apply_migrations(data)
        return data

    def save_index(self, data: dict) -> None:
        """Encrypt and write password index."""
        self.encryption_manager.save_json_data(data, self.index_file)

    def get_encrypted_index(self) -> Optional[bytes]:
        """Return the encrypted index bytes if present."""
        return self.encryption_manager.get_encrypted_index()

    def decrypt_and_save_index_from_nostr(self, encrypted_data: bytes) -> None:
        """Decrypt Nostr payload and overwrite the local index."""
        self.encryption_manager.decrypt_and_save_index_from_nostr(encrypted_data)

    # ----- Config helpers -----
    def load_config(self) -> dict:
        """Load decrypted configuration."""
        return self.encryption_manager.load_json_data(self.config_file)

    def save_config(self, config: dict) -> None:
        """Encrypt and persist configuration."""
        self.encryption_manager.save_json_data(config, self.config_file)
