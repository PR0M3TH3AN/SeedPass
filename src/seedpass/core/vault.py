"""Vault utilities for reading and writing encrypted files."""

from pathlib import Path
from typing import Optional, Union
from os import PathLike
import shutil

from termcolor import colored

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
        self.migrated_from_legacy = False

    def set_encryption_manager(self, manager: EncryptionManager) -> None:
        """Replace the internal encryption manager."""
        self.encryption_manager = manager

    # ----- Password index helpers -----
    def load_index(self, *, return_migration_flag: bool = False):
        """Return decrypted password index data, applying migrations.

        If a legacy ``seedpass_passwords_db.json.enc`` file is detected, the
        user is prompted to migrate it. A backup copy of the legacy file (and
        its checksum) is saved under ``legacy_backups`` within the fingerprint
        directory before renaming to the new filename.
        """

        legacy_file = self.fingerprint_dir / "seedpass_passwords_db.json.enc"
        self.migrated_from_legacy = False
        legacy_detected = False
        backup_dir = None
        if legacy_file.exists() and not self.index_file.exists():
            print(colored("Legacy index detected.", "yellow"))
            resp = (
                input("Would you like to migrate this to the new index format? [y/N]: ")
                .strip()
                .lower()
            )
            if resp != "y":
                raise RuntimeError("Migration declined by user")

            legacy_checksum = (
                self.fingerprint_dir / "seedpass_passwords_db_checksum.txt"
            )
            backup_dir = self.fingerprint_dir / "legacy_backups"
            backup_dir.mkdir(exist_ok=True)
            shutil.copy2(legacy_file, backup_dir / legacy_file.name)
            if legacy_checksum.exists():
                shutil.copy2(legacy_checksum, backup_dir / legacy_checksum.name)

            legacy_file.rename(self.index_file)
            if legacy_checksum.exists():
                legacy_checksum.rename(
                    self.fingerprint_dir / "seedpass_entries_db_checksum.txt"
                )

            # Remove any leftover legacy files to avoid triggering migration again
            for stray in self.fingerprint_dir.glob("seedpass_passwords_db*.enc"):
                try:
                    stray.unlink()
                except FileNotFoundError:
                    pass
            stray_checksum = self.fingerprint_dir / "seedpass_passwords_db_checksum.txt"
            if stray_checksum.exists():
                stray_checksum.unlink()

            legacy_detected = True
            print(
                colored(
                    "Migration complete. Original index backed up to 'legacy_backups'",
                    "green",
                )
            )

        try:
            data = self.encryption_manager.load_json_data(self.index_file)
            migration_performed = getattr(
                self.encryption_manager, "last_migration_performed", False
            )
        except Exception as exc:  # noqa: BLE001 - surface clear error and restore
            if legacy_detected and backup_dir is not None:
                backup_file = backup_dir / legacy_file.name
                legacy_checksum_path = (
                    self.fingerprint_dir / "seedpass_passwords_db_checksum.txt"
                )
                backup_checksum = backup_dir / legacy_checksum_path.name
                try:
                    if self.index_file.exists():
                        self.index_file.unlink()
                    shutil.copy2(backup_file, legacy_file)
                    checksum_new = (
                        self.fingerprint_dir / "seedpass_entries_db_checksum.txt"
                    )
                    if checksum_new.exists():
                        checksum_new.unlink()
                    if backup_checksum.exists():
                        shutil.copy2(backup_checksum, legacy_checksum_path)
                finally:
                    self.migrated_from_legacy = False
            raise RuntimeError(f"Migration failed: {exc}") from exc

        from .migrations import apply_migrations, LATEST_VERSION

        version = data.get("schema_version", 0)
        if version > LATEST_VERSION:
            raise ValueError(
                f"File schema version {version} is newer than supported {LATEST_VERSION}"
            )
        schema_migrated = version < LATEST_VERSION

        try:
            data = apply_migrations(data)
            if schema_migrated:
                self.encryption_manager.save_json_data(data, self.index_file)
                self.encryption_manager.update_checksum(self.index_file)
        except Exception as exc:  # noqa: BLE001 - surface clear error and restore
            if legacy_detected and backup_dir is not None:
                backup_file = backup_dir / legacy_file.name
                legacy_checksum_path = (
                    self.fingerprint_dir / "seedpass_passwords_db_checksum.txt"
                )
                backup_checksum = backup_dir / legacy_checksum_path.name
                try:
                    if self.index_file.exists():
                        self.index_file.unlink()
                    shutil.copy2(backup_file, legacy_file)
                    checksum_new = (
                        self.fingerprint_dir / "seedpass_entries_db_checksum.txt"
                    )
                    if checksum_new.exists():
                        checksum_new.unlink()
                    if backup_checksum.exists():
                        shutil.copy2(backup_checksum, legacy_checksum_path)
                finally:
                    self.migrated_from_legacy = False
            raise RuntimeError(f"Migration failed: {exc}") from exc

        self.migrated_from_legacy = (
            legacy_detected or migration_performed or schema_migrated
        )
        if return_migration_flag:
            return data, self.migrated_from_legacy
        return data

    def save_index(self, data: dict) -> None:
        """Encrypt and write password index."""
        self.encryption_manager.save_json_data(data, self.index_file)

    def get_encrypted_index(self) -> Optional[bytes]:
        """Return the encrypted index bytes if present."""
        return self.encryption_manager.get_encrypted_index()

    def decrypt_and_save_index_from_nostr(
        self,
        encrypted_data: bytes,
        *,
        strict: bool = True,
        merge: bool = False,
        return_migration_flag: bool = False,
    ):
        """Decrypt Nostr payload and update the local index.

        Returns ``True``/``False`` for success by default. When
        ``return_migration_flag`` is ``True`` a tuple ``(success, migrated)`` is
        returned, where ``migrated`` indicates whether any legacy migration
        occurred.
        """
        result = self.encryption_manager.decrypt_and_save_index_from_nostr(
            encrypted_data, strict=strict, merge=merge
        )
        self.migrated_from_legacy = result and getattr(
            self.encryption_manager, "last_migration_performed", False
        )
        if return_migration_flag:
            return result, self.migrated_from_legacy
        return result

    # ----- Config helpers -----
    def load_config(self) -> dict:
        """Load decrypted configuration."""
        return self.encryption_manager.load_json_data(self.config_file)

    def save_config(self, config: dict) -> None:
        """Encrypt and persist configuration."""
        self.encryption_manager.save_json_data(config, self.config_file)
