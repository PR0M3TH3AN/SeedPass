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
import os
import shutil
import time
import traceback
from typing import Optional, Tuple, Dict, Any, List
from pathlib import Path

from termcolor import colored

from password_manager.encryption import EncryptionManager
from utils.file_lock import lock_file

import fcntl

# Instantiate the logger
logger = logging.getLogger(__name__)


class EntryManager:
    def __init__(self, encryption_manager: EncryptionManager, fingerprint_dir: Path):
        """
        Initializes the EntryManager with the EncryptionManager and fingerprint directory.

        :param encryption_manager: The encryption manager instance.
        :param fingerprint_dir: The directory corresponding to the fingerprint.
        """
        self.encryption_manager = encryption_manager
        self.fingerprint_dir = fingerprint_dir

        # Use paths relative to the fingerprint directory
        self.index_file = self.fingerprint_dir / "seedpass_passwords_db.json.enc"
        self.checksum_file = self.fingerprint_dir / "seedpass_passwords_db_checksum.txt"

        logger.debug(f"EntryManager initialized with index file at {self.index_file}")

    def _load_index(self) -> Dict[str, Any]:
        if self.index_file.exists():
            try:
                data = self.encryption_manager.load_json_data(self.index_file)
                logger.debug("Index loaded successfully.")
                return data
            except Exception as e:
                logger.error(f"Failed to load index: {e}")
                return {"passwords": {}}
        else:
            logger.info(
                f"Index file '{self.index_file}' not found. Initializing new password database."
            )
            return {"passwords": {}}

    def _save_index(self, data: Dict[str, Any]) -> None:
        try:
            self.encryption_manager.save_json_data(data, self.index_file)
            logger.debug("Index saved successfully.")
        except Exception as e:
            logger.error(f"Failed to save index: {e}")
            raise

    def get_next_index(self) -> int:
        """
        Retrieves the next available index for a new password entry.

        :return: The next index number as an integer.
        """
        try:
            data = self.encryption_manager.load_json_data(self.index_file)
            if "passwords" in data and isinstance(data["passwords"], dict):
                indices = [int(idx) for idx in data["passwords"].keys()]
                next_index = max(indices) + 1 if indices else 0
            else:
                next_index = 0
            logger.debug(f"Next index determined: {next_index}")
            return next_index
        except Exception as e:
            logger.error(f"Error determining next index: {e}")
            logger.error(traceback.format_exc())
            print(colored(f"Error determining next index: {e}", "red"))
            sys.exit(1)

    def add_entry(
        self,
        website_name: str,
        length: int,
        username: Optional[str] = None,
        url: Optional[str] = None,
        blacklisted: bool = False,
    ) -> int:
        """
        Adds a new password entry to the encrypted JSON index file.

        :param website_name: The name of the website.
        :param length: The desired length of the password.
        :param username: (Optional) The username associated with the website.
        :param url: (Optional) The URL of the website.
        :param blacklisted: (Optional) Whether the password is blacklisted. Defaults to False.
        :return: The assigned index of the new entry.
        """
        try:
            index = self.get_next_index()
            data = self.encryption_manager.load_json_data(self.index_file)

            data["passwords"][str(index)] = {
                "website": website_name,
                "length": length,
                "username": username if username else "",
                "url": url if url else "",
                "blacklisted": blacklisted,
            }

            logger.debug(
                f"Added entry at index {index}: {data['passwords'][str(index)]}"
            )

            self._save_index(data)
            self.update_checksum()
            self.backup_index_file()

            logger.info(f"Entry added successfully at index {index}.")
            print(colored(f"[+] Entry added successfully at index {index}.", "green"))

            return index  # Return the assigned index

        except Exception as e:
            logger.error(f"Failed to add entry: {e}")
            logger.error(traceback.format_exc())
            print(colored(f"Error: Failed to add entry: {e}", "red"))
            sys.exit(1)

    def get_encrypted_index(self) -> Optional[bytes]:
        """
        Retrieves the encrypted password index file's contents.

        :return: The encrypted data as bytes, or None if retrieval fails.
        """
        try:
            if not self.index_file.exists():
                logger.error(f"Index file '{self.index_file}' does not exist.")
                print(
                    colored(
                        f"Error: Index file '{self.index_file}' does not exist.", "red"
                    )
                )
                return None

            with open(self.index_file, "rb") as file:
                encrypted_data = file.read()
                logger.debug("Encrypted index file data retrieved successfully.")
                return encrypted_data
        except Exception as e:
            logger.error(f"Failed to retrieve encrypted index file: {e}")
            logger.error(traceback.format_exc())
            print(
                colored(f"Error: Failed to retrieve encrypted index file: {e}", "red")
            )
            return None

    def retrieve_entry(self, index: int) -> Optional[Dict[str, Any]]:
        """
        Retrieves a password entry based on the provided index.

        :param index: The index number of the password entry.
        :return: A dictionary containing the entry details or None if not found.
        """
        try:
            data = self.encryption_manager.load_json_data(self.index_file)
            entry = data.get("passwords", {}).get(str(index))

            if entry:
                logger.debug(f"Retrieved entry at index {index}: {entry}")
                return entry
            else:
                logger.warning(f"No entry found at index {index}.")
                print(colored(f"Warning: No entry found at index {index}.", "yellow"))
                return None

        except Exception as e:
            logger.error(f"Failed to retrieve entry at index {index}: {e}")
            logger.error(traceback.format_exc())
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
    ) -> None:
        """
        Modifies an existing password entry based on the provided index and new values.

        :param index: The index number of the password entry to modify.
        :param username: (Optional) The new username.
        :param url: (Optional) The new URL.
        :param blacklisted: (Optional) The new blacklist status.
        """
        try:
            data = self.encryption_manager.load_json_data(self.index_file)
            entry = data.get("passwords", {}).get(str(index))

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

            data["passwords"][str(index)] = entry
            logger.debug(f"Modified entry at index {index}: {entry}")

            self._save_index(data)
            self.update_checksum()
            self.backup_index_file()

            logger.info(f"Entry at index {index} modified successfully.")
            print(
                colored(f"[+] Entry at index {index} modified successfully.", "green")
            )

        except Exception as e:
            logger.error(f"Failed to modify entry at index {index}: {e}")
            logger.error(traceback.format_exc())
            print(
                colored(f"Error: Failed to modify entry at index {index}: {e}", "red")
            )

    def list_entries(self) -> List[Tuple[int, str, Optional[str], Optional[str], bool]]:
        """
        Lists all password entries in the index.

        :return: A list of tuples containing entry details: (index, website, username, url, blacklisted)
        """
        try:
            data = self.encryption_manager.load_json_data()
            passwords = data.get("passwords", {})

            if not passwords:
                logger.info("No password entries found.")
                print(colored("No password entries found.", "yellow"))
                return []

            entries = []
            for idx, entry in sorted(passwords.items(), key=lambda x: int(x[0])):
                entries.append(
                    (
                        int(idx),
                        entry.get("website", ""),
                        entry.get("username", ""),
                        entry.get("url", ""),
                        entry.get("blacklisted", False),
                    )
                )

            logger.debug(f"Total entries found: {len(entries)}")
            for entry in entries:
                print(colored(f"Index: {entry[0]}", "cyan"))
                print(colored(f"  Website: {entry[1]}", "cyan"))
                print(colored(f"  Username: {entry[2] or 'N/A'}", "cyan"))
                print(colored(f"  URL: {entry[3] or 'N/A'}", "cyan"))
                print(colored(f"  Blacklisted: {'Yes' if entry[4] else 'No'}", "cyan"))
                print("-" * 40)

            return entries

        except Exception as e:
            logger.error(f"Failed to list entries: {e}")
            logger.error(traceback.format_exc())  # Log full traceback
            print(colored(f"Error: Failed to list entries: {e}", "red"))
            return []

    def delete_entry(self, index: int) -> None:
        """
        Deletes a password entry based on the provided index.

        :param index: The index number of the password entry to delete.
        """
        try:
            data = self.encryption_manager.load_json_data()
            if "passwords" in data and str(index) in data["passwords"]:
                del data["passwords"][str(index)]
                logger.debug(f"Deleted entry at index {index}.")
                self.encryption_manager.save_json_data(data)
                self.update_checksum()
                self.backup_index_file()
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
            logger.error(f"Failed to delete entry at index {index}: {e}")
            logger.error(traceback.format_exc())  # Log full traceback
            print(
                colored(f"Error: Failed to delete entry at index {index}: {e}", "red")
            )

    def update_checksum(self) -> None:
        """
        Updates the checksum file for the password database to ensure data integrity.
        """
        try:
            data = self.encryption_manager.load_json_data(self.index_file)
            json_content = json.dumps(data, indent=4)
            checksum = hashlib.sha256(json_content.encode("utf-8")).hexdigest()

            # Construct the full path for the checksum file
            checksum_path = self.fingerprint_dir / self.checksum_file

            with open(checksum_path, "w") as f:
                f.write(checksum)

            logger.debug(f"Checksum updated and written to '{checksum_path}'.")
            print(colored(f"[+] Checksum updated successfully.", "green"))

        except Exception as e:
            logger.error(f"Failed to update checksum: {e}")
            logger.error(traceback.format_exc())  # Log full traceback
            print(colored(f"Error: Failed to update checksum: {e}", "red"))

    def backup_index_file(self) -> None:
        """
        Creates a backup of the encrypted JSON index file to prevent data loss.
        """
        try:
            index_file_path = self.fingerprint_dir / self.index_file
            if not index_file_path.exists():
                logger.warning(
                    f"Index file '{index_file_path}' does not exist. No backup created."
                )
                return

            timestamp = int(time.time())
            backup_filename = f"passwords_db_backup_{timestamp}.json.enc"
            backup_path = self.fingerprint_dir / backup_filename

            with open(index_file_path, "rb") as original_file, open(
                backup_path, "wb"
            ) as backup_file:
                shutil.copyfileobj(original_file, backup_file)

            logger.debug(f"Backup created at '{backup_path}'.")
            print(colored(f"[+] Backup created at '{backup_path}'.", "green"))

        except Exception as e:
            logger.error(f"Failed to create backup: {e}")
            logger.error(traceback.format_exc())  # Log full traceback
            print(colored(f"Warning: Failed to create backup: {e}", "yellow"))

    def restore_from_backup(self, backup_path: str) -> None:
        """
        Restores the index file from a specified backup file.

        :param backup_path: The file path of the backup to restore from.
        """
        try:
            if not os.path.exists(backup_path):
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
            logger.error(f"Failed to restore from backup '{backup_path}': {e}")
            logger.error(traceback.format_exc())  # Log full traceback
            print(
                colored(
                    f"Error: Failed to restore from backup '{backup_path}': {e}", "red"
                )
            )

    def list_all_entries(self) -> None:
        """
        Displays all password entries in a formatted manner.
        """
        try:
            entries = self.list_entries()
            if not entries:
                print(colored("No entries to display.", "yellow"))
                return

            print(colored("\n[+] Listing All Password Entries:\n", "green"))
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
            logger.error(f"Failed to list all entries: {e}")
            logger.error(traceback.format_exc())  # Log full traceback
            print(colored(f"Error: Failed to list all entries: {e}", "red"))
            return


# Example usage (this part should be removed or commented out when integrating into the larger application)
if __name__ == "__main__":
    from password_manager.encryption import (
        EncryptionManager,
    )  # Ensure this import is correct based on your project structure

    # Initialize EncryptionManager with a dummy key for demonstration purposes
    # Replace 'your-fernet-key' with your actual Fernet key
    try:
        dummy_key = Fernet.generate_key()
        encryption_manager = EncryptionManager(dummy_key)
    except Exception as e:
        logger.error(f"Failed to initialize EncryptionManager: {e}")
        print(colored(f"Error: Failed to initialize EncryptionManager: {e}", "red"))
        sys.exit(1)

    # Initialize EntryManager
    try:
        entry_manager = EntryManager(encryption_manager)
    except Exception as e:
        logger.error(f"Failed to initialize EntryManager: {e}")
        print(colored(f"Error: Failed to initialize EntryManager: {e}", "red"))
        sys.exit(1)

    # Example operations
    # These would typically be triggered by user interactions, e.g., via a CLI menu
    # Uncomment and modify the following lines as needed for testing

    # Adding an entry
    # entry_manager.add_entry("Example Website", 16, "user123", "https://example.com", False)

    # Listing all entries
    # entry_manager.list_all_entries()

    # Retrieving an entry
    # entry = entry_manager.retrieve_entry(0)
    # if entry:
    #     print(entry)

    # Modifying an entry
    # entry_manager.modify_entry(0, username="new_user123")

    # Deleting an entry
    # entry_manager.delete_entry(0)

    # Restoring from a backup
    # entry_manager.restore_from_backup("path_to_backup_file.json.enc")
