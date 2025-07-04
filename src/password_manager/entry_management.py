# password_manager/entry_management.py

"""
Entry Management Module

This module implements the EntryManager class, responsible for handling
operations related to managing password entries in the deterministic password manager.
It provides methods to add, retrieve, modify, and list password entries, ensuring
that all changes are securely encrypted and properly indexed.

Ensure that all dependencies are installed and properly configured in your environment.

Never use or suggest using Random Salt. The purpose of this password manager is to derive
completely deterministic passwords from a BIP-85 seed, ensuring that passwords are generated
the same way every time. Salts would break this functionality and are not suitable for this software.
"""

import json
import logging
import hashlib
import sys
import shutil
from typing import Optional, Tuple, Dict, Any, List
from pathlib import Path

from termcolor import colored
from password_manager.migrations import LATEST_VERSION
from password_manager.entry_types import EntryType
from password_manager.totp import TotpManager

from password_manager.vault import Vault
from password_manager.backup import BackupManager


# Instantiate the logger
logger = logging.getLogger(__name__)


class EntryManager:
    def __init__(self, vault: Vault, backup_manager: BackupManager):
        """Initialize the EntryManager.

        Parameters:
            vault: The Vault instance for file access.
            backup_manager: Manages creation of entry database backups.
        """
        self.vault = vault
        self.backup_manager = backup_manager
        self.fingerprint_dir = backup_manager.fingerprint_dir

        # Use paths relative to the fingerprint directory
        self.index_file = self.fingerprint_dir / "seedpass_entries_db.json.enc"
        self.checksum_file = self.fingerprint_dir / "seedpass_entries_db_checksum.txt"

        logger.debug(f"EntryManager initialized with index file at {self.index_file}")

    def _load_index(self) -> Dict[str, Any]:
        if self.index_file.exists():
            try:
                data = self.vault.load_index()
                # Normalize legacy fields
                for entry in data.get("entries", {}).values():
                    if "type" not in entry and "kind" in entry:
                        entry["type"] = entry["kind"]
                    if "kind" not in entry:
                        entry["kind"] = entry.get("type", EntryType.PASSWORD.value)
                    entry.setdefault("type", entry["kind"])
                logger.debug("Index loaded successfully.")
                return data
            except Exception as e:
                logger.error(f"Failed to load index: {e}")
                return {"schema_version": LATEST_VERSION, "entries": {}}
        else:
            logger.info(
                f"Index file '{self.index_file}' not found. Initializing new entries database."
            )
            return {"schema_version": LATEST_VERSION, "entries": {}}

    def _save_index(self, data: Dict[str, Any]) -> None:
        try:
            self.vault.save_index(data)
            logger.debug("Index saved successfully.")
        except Exception as e:
            logger.error(f"Failed to save index: {e}")
            raise

    def get_next_index(self) -> int:
        """
        Retrieves the next available index for a new entry.

        :return: The next index number as an integer.
        """
        try:
            data = self.vault.load_index()
            if "entries" in data and isinstance(data["entries"], dict):
                indices = [int(idx) for idx in data["entries"].keys()]
                next_index = max(indices) + 1 if indices else 0
            else:
                next_index = 0
            logger.debug(f"Next index determined: {next_index}")
            return next_index
        except Exception as e:
            logger.error(f"Error determining next index: {e}", exc_info=True)
            print(colored(f"Error determining next index: {e}", "red"))
            sys.exit(1)

    def add_entry(
        self,
        website_name: str,
        length: int,
        username: Optional[str] = None,
        url: Optional[str] = None,
        blacklisted: bool = False,
        notes: str = "",
        custom_fields: List[Dict[str, Any]] | None = None,
    ) -> int:
        """
        Adds a new entry to the encrypted JSON index file.

        :param website_name: The name of the website.
        :param length: The desired length of the password.
        :param username: (Optional) The username associated with the website.
        :param url: (Optional) The URL of the website.
        :param blacklisted: (Optional) Whether the password is blacklisted. Defaults to False.
        :param notes: (Optional) Extra notes to attach to the entry.
        :return: The assigned index of the new entry.
        """
        try:
            index = self.get_next_index()
            data = self.vault.load_index()

            data.setdefault("entries", {})
            data["entries"][str(index)] = {
                "website": website_name,
                "length": length,
                "username": username if username else "",
                "url": url if url else "",
                "blacklisted": blacklisted,
                "type": EntryType.PASSWORD.value,
                "kind": EntryType.PASSWORD.value,
                "notes": notes,
                "custom_fields": custom_fields or [],
            }

            logger.debug(f"Added entry at index {index}: {data['entries'][str(index)]}")

            self._save_index(data)
            self.update_checksum()
            self.backup_manager.create_backup()

            logger.info(f"Entry added successfully at index {index}.")
            print(colored(f"[+] Entry added successfully at index {index}.", "green"))

            return index  # Return the assigned index

        except Exception as e:
            logger.error(f"Failed to add entry: {e}", exc_info=True)
            print(colored(f"Error: Failed to add entry: {e}", "red"))
            sys.exit(1)

    def get_next_totp_index(self) -> int:
        """Return the next available derivation index for TOTP secrets."""
        data = self.vault.load_index()
        entries = data.get("entries", {})
        indices = [
            int(v.get("index", 0))
            for v in entries.values()
            if (
                v.get("type") == EntryType.TOTP.value
                or v.get("kind") == EntryType.TOTP.value
            )
        ]
        return (max(indices) + 1) if indices else 0

    def add_totp(
        self,
        label: str,
        parent_seed: str,
        *,
        secret: str | None = None,
        index: int | None = None,
        period: int = 30,
        digits: int = 6,
    ) -> str:
        """Add a new TOTP entry and return the provisioning URI."""
        entry_id = self.get_next_index()
        data = self.vault.load_index()
        data.setdefault("entries", {})

        if secret is None:
            if index is None:
                index = self.get_next_totp_index()
            secret = TotpManager.derive_secret(parent_seed, index)
            entry = {
                "type": EntryType.TOTP.value,
                "kind": EntryType.TOTP.value,
                "label": label,
                "index": index,
                "period": period,
                "digits": digits,
            }
        else:
            entry = {
                "type": EntryType.TOTP.value,
                "kind": EntryType.TOTP.value,
                "label": label,
                "secret": secret,
                "period": period,
                "digits": digits,
            }

        data["entries"][str(entry_id)] = entry

        self._save_index(data)
        self.update_checksum()
        self.backup_manager.create_backup()

        try:
            return TotpManager.make_otpauth_uri(label, secret, period, digits)
        except Exception as e:
            logger.error(f"Failed to generate otpauth URI: {e}")
            raise

    def add_ssh_key(
        self, parent_seed: str, index: int | None = None, notes: str = ""
    ) -> int:
        """Add a new SSH key pair entry.

        The provided ``index`` serves both as the vault entry identifier and
        derivation index for the key. If not supplied, the next available index
        is used. Only metadata is stored – keys are derived on demand.
        """

        if index is None:
            index = self.get_next_index()

        data = self.vault.load_index()
        data.setdefault("entries", {})
        data["entries"][str(index)] = {
            "type": EntryType.SSH.value,
            "kind": EntryType.SSH.value,
            "index": index,
            "notes": notes,
        }
        self._save_index(data)
        self.update_checksum()
        self.backup_manager.create_backup()
        return index

    def get_ssh_key_pair(self, index: int, parent_seed: str) -> tuple[str, str]:
        """Return the PEM formatted SSH key pair for the given entry."""

        entry = self.retrieve_entry(index)
        etype = entry.get("type") if entry else None
        kind = entry.get("kind") if entry else None
        if not entry or (etype != EntryType.SSH.value and kind != EntryType.SSH.value):
            raise ValueError("Entry is not an SSH key entry")

        from password_manager.password_generation import derive_ssh_key_pair

        key_index = int(entry.get("index", index))
        return derive_ssh_key_pair(parent_seed, key_index)

    def add_pgp_key(
        self,
        parent_seed: str,
        index: int | None = None,
        key_type: str = "ed25519",
        user_id: str = "",
        notes: str = "",
    ) -> int:
        """Add a new PGP key entry."""

        if index is None:
            index = self.get_next_index()

        data = self.vault.load_index()
        data.setdefault("entries", {})
        data["entries"][str(index)] = {
            "type": EntryType.PGP.value,
            "kind": EntryType.PGP.value,
            "index": index,
            "key_type": key_type,
            "user_id": user_id,
            "notes": notes,
        }
        self._save_index(data)
        self.update_checksum()
        self.backup_manager.create_backup()
        return index

    def get_pgp_key(self, index: int, parent_seed: str) -> tuple[str, str]:
        """Return the armored PGP private key and fingerprint for the entry."""

        entry = self.retrieve_entry(index)
        etype = entry.get("type") if entry else None
        kind = entry.get("kind") if entry else None
        if not entry or (etype != EntryType.PGP.value and kind != EntryType.PGP.value):
            raise ValueError("Entry is not a PGP key entry")

        from password_manager.password_generation import derive_pgp_key
        from local_bip85.bip85 import BIP85
        from bip_utils import Bip39SeedGenerator

        seed_bytes = Bip39SeedGenerator(parent_seed).Generate()
        bip85 = BIP85(seed_bytes)

        key_idx = int(entry.get("index", index))
        key_type = entry.get("key_type", "ed25519")
        user_id = entry.get("user_id", "")
        return derive_pgp_key(bip85, key_idx, key_type, user_id)

    def add_seed(
        self,
        parent_seed: str,
        index: int | None = None,
        words_num: int = 24,
        notes: str = "",
    ) -> int:
        """Add a new derived seed phrase entry."""

        if index is None:
            index = self.get_next_index()

        data = self.vault.load_index()
        data.setdefault("entries", {})
        data["entries"][str(index)] = {
            "type": EntryType.SEED.value,
            "kind": EntryType.SEED.value,
            "index": index,
            "words": words_num,
            "notes": notes,
        }
        self._save_index(data)
        self.update_checksum()
        self.backup_manager.create_backup()
        return index

    def get_seed_phrase(self, index: int, parent_seed: str) -> str:
        """Return the mnemonic seed phrase for the given entry."""

        entry = self.retrieve_entry(index)
        etype = entry.get("type") if entry else None
        kind = entry.get("kind") if entry else None
        if not entry or (
            etype != EntryType.SEED.value and kind != EntryType.SEED.value
        ):
            raise ValueError("Entry is not a seed entry")

        from password_manager.password_generation import derive_seed_phrase
        from local_bip85.bip85 import BIP85
        from bip_utils import Bip39SeedGenerator

        seed_bytes = Bip39SeedGenerator(parent_seed).Generate()
        bip85 = BIP85(seed_bytes)

        words = int(entry.get("words", 24))
        seed_index = int(entry.get("index", index))
        return derive_seed_phrase(bip85, seed_index, words)

    def get_totp_code(
        self, index: int, parent_seed: str | None = None, timestamp: int | None = None
    ) -> str:
        """Return the current TOTP code for the specified entry."""
        entry = self.retrieve_entry(index)
        etype = entry.get("type") if entry else None
        kind = entry.get("kind") if entry else None
        if not entry or (
            etype != EntryType.TOTP.value and kind != EntryType.TOTP.value
        ):
            raise ValueError("Entry is not a TOTP entry")
        if "secret" in entry:
            return TotpManager.current_code_from_secret(entry["secret"], timestamp)
        if parent_seed is None:
            raise ValueError("Seed required for derived TOTP")
        totp_index = int(entry.get("index", 0))
        return TotpManager.current_code(parent_seed, totp_index, timestamp)

    def get_totp_time_remaining(self, index: int) -> int:
        """Return seconds remaining in the TOTP period for the given entry."""
        entry = self.retrieve_entry(index)
        etype = entry.get("type") if entry else None
        kind = entry.get("kind") if entry else None
        if not entry or (
            etype != EntryType.TOTP.value and kind != EntryType.TOTP.value
        ):
            raise ValueError("Entry is not a TOTP entry")

        period = int(entry.get("period", 30))
        return TotpManager.time_remaining(period)

    def get_encrypted_index(self) -> Optional[bytes]:
        """
        Retrieves the encrypted password index file's contents.

        :return: The encrypted data as bytes, or None if retrieval fails.
        """
        try:
            return self.vault.get_encrypted_index()
        except Exception as e:
            logger.error(f"Failed to retrieve encrypted index file: {e}", exc_info=True)
            print(
                colored(f"Error: Failed to retrieve encrypted index file: {e}", "red")
            )
            return None

    def retrieve_entry(self, index: int) -> Optional[Dict[str, Any]]:
        """
        Retrieves an entry based on the provided index.

        :param index: The index number of the entry.
        :return: A dictionary containing the entry details or None if not found.
        """
        try:
            data = self.vault.load_index()
            entry = data.get("entries", {}).get(str(index))

            if entry:
                if entry.get("type", entry.get("kind")) == EntryType.PASSWORD.value:
                    entry.setdefault("custom_fields", [])
                logger.debug(f"Retrieved entry at index {index}: {entry}")
                return entry
            else:
                logger.warning(f"No entry found at index {index}.")
                print(colored(f"Warning: No entry found at index {index}.", "yellow"))
                return None

        except Exception as e:
            logger.error(
                f"Failed to retrieve entry at index {index}: {e}", exc_info=True
            )
            print(
                colored(f"Error: Failed to retrieve entry at index {index}: {e}", "red")
            )
            return None

    def modify_entry(
        self,
        index: int,
        username: Optional[str] = None,
        url: Optional[str] = None,
        blacklisted: Optional[bool] = None,
        notes: Optional[str] = None,
        *,
        label: Optional[str] = None,
        period: Optional[int] = None,
        digits: Optional[int] = None,
        custom_fields: List[Dict[str, Any]] | None = None,
    ) -> None:
        """
        Modifies an existing entry based on the provided index and new values.

        :param index: The index number of the entry to modify.
        :param username: (Optional) The new username (password entries).
        :param url: (Optional) The new URL (password entries).
        :param blacklisted: (Optional) The new blacklist status.
        :param notes: (Optional) New notes to attach to the entry.
        :param label: (Optional) The new label for TOTP entries.
        :param period: (Optional) The new TOTP period in seconds.
        :param digits: (Optional) The new number of digits for TOTP codes.
        """
        try:
            data = self.vault.load_index()
            entry = data.get("entries", {}).get(str(index))

            if not entry:
                logger.warning(
                    f"No entry found at index {index}. Cannot modify non-existent entry."
                )
                print(
                    colored(
                        f"Warning: No entry found at index {index}. Cannot modify non-existent entry.",
                        "yellow",
                    )
                )
                return

            entry_type = entry.get("type", entry.get("kind", EntryType.PASSWORD.value))

            if entry_type == EntryType.TOTP.value:
                if label is not None:
                    entry["label"] = label
                    logger.debug(f"Updated label to '{label}' for index {index}.")
                if period is not None:
                    entry["period"] = period
                    logger.debug(f"Updated period to '{period}' for index {index}.")
                if digits is not None:
                    entry["digits"] = digits
                    logger.debug(f"Updated digits to '{digits}' for index {index}.")
            else:
                if username is not None:
                    entry["username"] = username
                    logger.debug(f"Updated username to '{username}' for index {index}.")
                if url is not None:
                    entry["url"] = url
                    logger.debug(f"Updated URL to '{url}' for index {index}.")

            if blacklisted is not None:
                entry["blacklisted"] = blacklisted
                logger.debug(
                    f"Updated blacklist status to '{blacklisted}' for index {index}."
                )

            if notes is not None:
                entry["notes"] = notes
                logger.debug(f"Updated notes for index {index}.")

            if custom_fields is not None:
                entry["custom_fields"] = custom_fields
                logger.debug(
                    f"Updated custom fields for index {index}: {custom_fields}"
                )

            data["entries"][str(index)] = entry
            logger.debug(f"Modified entry at index {index}: {entry}")

            self._save_index(data)
            self.update_checksum()
            self.backup_manager.create_backup()

            logger.info(f"Entry at index {index} modified successfully.")
            print(
                colored(f"[+] Entry at index {index} modified successfully.", "green")
            )

        except Exception as e:
            logger.error(f"Failed to modify entry at index {index}: {e}", exc_info=True)
            print(
                colored(f"Error: Failed to modify entry at index {index}: {e}", "red")
            )

    def list_entries(
        self, sort_by: str = "index", filter_kind: str | None = None
    ) -> List[Tuple[int, str, Optional[str], Optional[str], bool]]:
        """List entries in the index with optional sorting and filtering."""
        try:
            data = self.vault.load_index()
            entries_data = data.get("entries", {})

            if not entries_data:
                logger.info("No entries found.")
                print(colored("No entries found.", "yellow"))
                return []

            def sort_key(item: Tuple[str, Dict[str, Any]]):
                idx_str, entry = item
                if sort_by == "index":
                    return int(idx_str)
                if sort_by == "website":
                    return entry.get("website", "").lower()
                if sort_by == "username":
                    return entry.get("username", "").lower()
                raise ValueError("sort_by must be 'index', 'website', or 'username'")

            sorted_items = sorted(entries_data.items(), key=sort_key)

            filtered_items: List[Tuple[int, Dict[str, Any]]] = []
            for idx_str, entry in sorted_items:
                if (
                    filter_kind is not None
                    and entry.get("type", entry.get("kind", EntryType.PASSWORD.value))
                    != filter_kind
                ):
                    continue
                filtered_items.append((int(idx_str), entry))

            entries: List[Tuple[int, str, Optional[str], Optional[str], bool]] = []
            for idx, entry in filtered_items:
                etype = entry.get("type", entry.get("kind", EntryType.PASSWORD.value))
                if etype == EntryType.TOTP.value:
                    entries.append((idx, entry.get("label", ""), None, None, False))
                else:
                    entries.append(
                        (
                            idx,
                            entry.get("website", ""),
                            entry.get("username", ""),
                            entry.get("url", ""),
                            entry.get("blacklisted", False),
                        )
                    )

            logger.debug(f"Total entries found: {len(entries)}")
            for idx, entry in filtered_items:
                etype = entry.get("type", entry.get("kind", EntryType.PASSWORD.value))
                print(colored(f"Index: {idx}", "cyan"))
                if etype == EntryType.TOTP.value:
                    print(colored("  Type: TOTP", "cyan"))
                    print(colored(f"  Label: {entry.get('label', '')}", "cyan"))
                    print(colored(f"  Derivation Index: {entry.get('index')}", "cyan"))
                    print(
                        colored(
                            f"  Period: {entry.get('period', 30)}s  Digits: {entry.get('digits', 6)}",
                            "cyan",
                        )
                    )
                else:
                    print(colored(f"  Website: {entry.get('website', '')}", "cyan"))
                    print(
                        colored(f"  Username: {entry.get('username') or 'N/A'}", "cyan")
                    )
                    print(colored(f"  URL: {entry.get('url') or 'N/A'}", "cyan"))
                    print(
                        colored(
                            f"  Blacklisted: {'Yes' if entry.get('blacklisted', False) else 'No'}",
                            "cyan",
                        )
                    )
                print("-" * 40)

            return entries

        except Exception as e:
            logger.error(f"Failed to list entries: {e}", exc_info=True)
            print(colored(f"Error: Failed to list entries: {e}", "red"))
            return []

    def search_entries(
        self, query: str
    ) -> List[Tuple[int, str, Optional[str], Optional[str], bool]]:
        """Return entries matching the query across common fields."""
        data = self.vault.load_index()
        entries_data = data.get("entries", {})

        if not entries_data:
            return []

        query_lower = query.lower()
        results: List[Tuple[int, str, Optional[str], Optional[str], bool]] = []

        for idx, entry in sorted(entries_data.items(), key=lambda x: int(x[0])):
            etype = entry.get("type", entry.get("kind", EntryType.PASSWORD.value))
            if etype == EntryType.TOTP.value:
                label = entry.get("label", "")
                notes = entry.get("notes", "")
                if query_lower in label.lower() or query_lower in notes.lower():
                    results.append((int(idx), label, None, None, False))
            else:
                website = entry.get("website", "")
                username = entry.get("username", "")
                url = entry.get("url", "")
                notes = entry.get("notes", "")
                custom_fields = entry.get("custom_fields", [])
                custom_match = any(
                    query_lower in str(cf.get("label", "")).lower()
                    or query_lower in str(cf.get("value", "")).lower()
                    for cf in custom_fields
                )
                if (
                    query_lower in website.lower()
                    or query_lower in username.lower()
                    or query_lower in url.lower()
                    or query_lower in notes.lower()
                    or custom_match
                ):
                    results.append(
                        (
                            int(idx),
                            website,
                            username,
                            url,
                            entry.get("blacklisted", False),
                        )
                    )

        return results

    def delete_entry(self, index: int) -> None:
        """
        Deletes an entry based on the provided index.

        :param index: The index number of the entry to delete.
        """
        try:
            data = self.vault.load_index()
            if "entries" in data and str(index) in data["entries"]:
                del data["entries"][str(index)]
                logger.debug(f"Deleted entry at index {index}.")
                self.vault.save_index(data)
                self.update_checksum()
                self.backup_manager.create_backup()
                logger.info(f"Entry at index {index} deleted successfully.")
                print(
                    colored(
                        f"[+] Entry at index {index} deleted successfully.", "green"
                    )
                )
            else:
                logger.warning(
                    f"No entry found at index {index}. Cannot delete non-existent entry."
                )
                print(
                    colored(
                        f"Warning: No entry found at index {index}. Cannot delete non-existent entry.",
                        "yellow",
                    )
                )

        except Exception as e:
            logger.error(f"Failed to delete entry at index {index}: {e}", exc_info=True)
            print(
                colored(f"Error: Failed to delete entry at index {index}: {e}", "red")
            )

    def update_checksum(self) -> None:
        """
        Updates the checksum file for the password database to ensure data integrity.
        """
        try:
            data = self.vault.load_index()
            json_content = json.dumps(data, indent=4)
            checksum = hashlib.sha256(json_content.encode("utf-8")).hexdigest()

            # The checksum file path already includes the fingerprint directory
            checksum_path = self.checksum_file

            with open(checksum_path, "w") as f:
                f.write(checksum)

            logger.debug(f"Checksum updated and written to '{checksum_path}'.")
            print(colored(f"[+] Checksum updated successfully.", "green"))

        except Exception as e:
            logger.error(f"Failed to update checksum: {e}", exc_info=True)
            print(colored(f"Error: Failed to update checksum: {e}", "red"))

    def restore_from_backup(self, backup_path: str) -> None:
        """
        Restores the index file from a specified backup file.

        :param backup_path: The file path of the backup to restore from.
        """
        try:
            backup_path = Path(backup_path)
            if not backup_path.exists():
                logger.error(f"Backup file '{backup_path}' does not exist.")
                print(
                    colored(
                        f"Error: Backup file '{backup_path}' does not exist.", "red"
                    )
                )
                return

            with open(backup_path, "rb") as backup_file, open(
                self.index_file, "wb"
            ) as index_file:
                shutil.copyfileobj(backup_file, index_file)

            logger.debug(f"Index file restored from backup '{backup_path}'.")
            print(
                colored(
                    f"[+] Index file restored from backup '{backup_path}'.", "green"
                )
            )

            self.update_checksum()

        except Exception as e:
            logger.error(
                f"Failed to restore from backup '{backup_path}': {e}", exc_info=True
            )
            print(
                colored(
                    f"Error: Failed to restore from backup '{backup_path}': {e}", "red"
                )
            )

    def list_all_entries(
        self, sort_by: str = "index", filter_kind: str | None = None
    ) -> None:
        """Display all entries using :meth:`list_entries`."""
        try:
            entries = self.list_entries(sort_by=sort_by, filter_kind=filter_kind)
            if not entries:
                print(colored("No entries to display.", "yellow"))
                return

            print(colored("\n[+] Listing All Entries:\n", "green"))
            for entry in entries:
                index, website, username, url, blacklisted = entry
                print(colored(f"Index: {index}", "cyan"))
                print(colored(f"  Website: {website}", "cyan"))
                print(colored(f"  Username: {username or 'N/A'}", "cyan"))
                print(colored(f"  URL: {url or 'N/A'}", "cyan"))
                print(
                    colored(f"  Blacklisted: {'Yes' if blacklisted else 'No'}", "cyan")
                )
                print("-" * 40)

        except Exception as e:
            logger.error(f"Failed to list all entries: {e}", exc_info=True)
            print(colored(f"Error: Failed to list all entries: {e}", "red"))
            return
