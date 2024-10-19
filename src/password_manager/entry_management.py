# password_manager/entry_management.py

"""
Entry Management Module

This module implements the EntryManager class, responsible for handling
operations related to managing password entries in the deterministic password manager.
It provides methods to add, retrieve, modify, and list password entries, ensuring
that all changes are securely encrypted and properly indexed.

Dependencies:
- password_manager.encryption.EncryptionManager
- constants.INDEX_FILE
- constants.DATA_CHECKSUM_FILE
- utils.file_lock.lock_file
- colorama.Fore
- termcolor.colored
- logging
- json
- hashlib
- sys
- os

Ensure that all dependencies are installed and properly configured in your environment.

Never ever ever use or suggest to use Random Salt. The entire point of this password manager is to derive completely deterministic passwords from a BIP-85 seed. 
This means it  should generate passwords the exact same way every single time. Salts would break this functionality and is not appropriate for this softwares use case. 
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

from colorama import Fore
from termcolor import colored

from password_manager.encryption import EncryptionManager
from constants import INDEX_FILE, DATA_CHECKSUM_FILE
from utils.file_lock import lock_file

import fcntl  # Required for lock_type constants in lock_file

# Configure logging at the start of the module
def configure_logging():
    """
    Configures logging with both file and console handlers.
    Logs include the timestamp, log level, message, filename, and line number.
    Only ERROR and higher-level messages are shown in the terminal, while all messages
    are logged in the log file.
    """
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)  # Set to DEBUG for detailed output

    # Prevent adding multiple handlers if configure_logging is called multiple times
    if not logger.handlers:
        # Create the 'logs' folder if it doesn't exist
        if not os.path.exists('logs'):
            os.makedirs('logs')

        # Create handlers
        c_handler = logging.StreamHandler()
        f_handler = logging.FileHandler(os.path.join('logs', 'entry_management.log'))

        # Set levels: only errors and critical messages will be shown in the console
        c_handler.setLevel(logging.ERROR)  # Console will show ERROR and above
        f_handler.setLevel(logging.DEBUG)  # File will log everything from DEBUG and above

        # Create formatters and add them to handlers, include file and line number in log messages
        formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s [%(filename)s:%(lineno)d]'
        )
        c_handler.setFormatter(formatter)
        f_handler.setFormatter(formatter)

        # Add handlers to the logger
        logger.addHandler(c_handler)
        logger.addHandler(f_handler)

# Call the logging configuration function
configure_logging()

logger = logging.getLogger(__name__)

class EntryManager:
    """
    EntryManager Class

    Handles the creation, retrieval, modification, and listing of password entries
    within the encrypted password index. It ensures that all operations are performed
    securely, maintaining data integrity and confidentiality.
    """

    def __init__(self, encryption_manager: EncryptionManager):
        """
        Initializes the EntryManager with an instance of EncryptionManager.

        :param encryption_manager: An instance of EncryptionManager for handling encryption.
        """
        try:
            self.encryption_manager = encryption_manager
            logger.debug("EntryManager initialized with provided EncryptionManager.")
        except Exception as e:
            logger.error(f"Failed to initialize EntryManager: {e}")
            logger.error(traceback.format_exc())  # Log full traceback
            print(colored(f"Error: Failed to initialize EntryManager: {e}", 'red'))
            sys.exit(1)

    def get_next_index(self) -> int:
        """
        Retrieves the next available index for a new password entry.

        :return: The next index number as an integer.
        """
        try:
            data = self.encryption_manager.load_json_data()
            if 'passwords' in data and isinstance(data['passwords'], dict):
                indices = [int(idx) for idx in data['passwords'].keys()]
                next_index = max(indices) + 1 if indices else 0
            else:
                next_index = 0
            logger.debug(f"Next index determined: {next_index}")
            return next_index
        except Exception as e:
            logger.error(f"Error determining next index: {e}")
            logger.error(traceback.format_exc())  # Log full traceback
            print(colored(f"Error determining next index: {e}", 'red'))
            sys.exit(1)

    def add_entry(self, website_name: str, length: int, username: Optional[str] = None,
                url: Optional[str] = None, blacklisted: bool = False) -> int:
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
            data = self.encryption_manager.load_json_data()

            if 'passwords' not in data or not isinstance(data['passwords'], dict):
                data['passwords'] = {}
                logger.debug("'passwords' key was missing. Initialized empty 'passwords' dictionary.")

            data['passwords'][str(index)] = {
                'website': website_name,
                'length': length,
                'username': username if username else '',
                'url': url if url else '',
                'blacklisted': blacklisted
            }

            logger.debug(f"Added entry at index {index}: {data['passwords'][str(index)]}")

            self.encryption_manager.save_json_data(data)
            self.update_checksum()
            self.backup_index_file()

            logger.info(f"Entry added successfully at index {index}.")
            print(colored(f"[+] Entry added successfully at index {index}.", 'green'))

            return index  # Return the assigned index

        except Exception as e:
            logger.error(f"Failed to add entry: {e}")
            logger.error(traceback.format_exc())  # Log full traceback
            print(colored(f"Error: Failed to add entry: {e}", 'red'))
            sys.exit(1)

    def retrieve_entry(self, index: int) -> Optional[Dict[str, Any]]:
        """
        Retrieves a password entry based on the provided index.

        :param index: The index number of the password entry.
        :return: A dictionary containing the entry details or None if not found.
        """
        try:
            data = self.encryption_manager.load_json_data()
            entry = data.get('passwords', {}).get(str(index))

            if entry:
                logger.debug(f"Retrieved entry at index {index}: {entry}")
                return entry
            else:
                logger.warning(f"No entry found at index {index}.")
                print(colored(f"Warning: No entry found at index {index}.", 'yellow'))
                return None

        except Exception as e:
            logger.error(f"Failed to retrieve entry at index {index}: {e}")
            logger.error(traceback.format_exc())  # Log full traceback
            print(colored(f"Error: Failed to retrieve entry at index {index}: {e}", 'red'))
            return None

    def modify_entry(self, index: int, username: Optional[str] = None,
                    url: Optional[str] = None,
                    blacklisted: Optional[bool] = None) -> None:
        """
        Modifies an existing password entry based on the provided index and new values.

        :param index: The index number of the password entry to modify.
        :param username: (Optional) The new username.
        :param url: (Optional) The new URL.
        :param blacklisted: (Optional) The new blacklist status.
        """
        try:
            data = self.encryption_manager.load_json_data()
            entry = data.get('passwords', {}).get(str(index))

            if not entry:
                logger.warning(f"No entry found at index {index}. Cannot modify non-existent entry.")
                print(colored(f"Warning: No entry found at index {index}. Cannot modify non-existent entry.", 'yellow'))
                return

            if username is not None:
                entry['username'] = username
                logger.debug(f"Updated username to '{username}' for index {index}.")

            if url is not None:
                entry['url'] = url
                logger.debug(f"Updated URL to '{url}' for index {index}.")

            if blacklisted is not None:
                entry['blacklisted'] = blacklisted
                logger.debug(f"Updated blacklist status to '{blacklisted}' for index {index}.")

            data['passwords'][str(index)] = entry
            logger.debug(f"Modified entry at index {index}: {entry}")

            self.encryption_manager.save_json_data(data)
            self.update_checksum()
            self.backup_index_file()

            logger.info(f"Entry at index {index} modified successfully.")
            print(colored(f"[+] Entry at index {index} modified successfully.", 'green'))

        except Exception as e:
            logger.error(f"Failed to modify entry at index {index}: {e}")
            logger.error(traceback.format_exc())  # Log full traceback
            print(colored(f"Error: Failed to modify entry at index {index}: {e}", 'red'))

    def list_entries(self) -> List[Tuple[int, str, Optional[str], Optional[str], bool]]:
        """
        Lists all password entries in the index.

        :return: A list of tuples containing entry details: (index, website, username, url, blacklisted)
        """
        try:
            data = self.encryption_manager.load_json_data()
            passwords = data.get('passwords', {})

            if not passwords:
                logger.info("No password entries found.")
                print(colored("No password entries found.", 'yellow'))
                return []

            entries = []
            for idx, entry in sorted(passwords.items(), key=lambda x: int(x[0])):
                entries.append((
                    int(idx),
                    entry.get('website', ''),
                    entry.get('username', ''),
                    entry.get('url', ''),
                    entry.get('blacklisted', False)
                ))

            logger.debug(f"Total entries found: {len(entries)}")
            for entry in entries:
                print(colored(f"Index: {entry[0]}", 'cyan'))
                print(colored(f"  Website: {entry[1]}", 'cyan'))
                print(colored(f"  Username: {entry[2] or 'N/A'}", 'cyan'))
                print(colored(f"  URL: {entry[3] or 'N/A'}", 'cyan'))
                print(colored(f"  Blacklisted: {'Yes' if entry[4] else 'No'}", 'cyan'))
                print("-" * 40)

            return entries

        except Exception as e:
            logger.error(f"Failed to list entries: {e}")
            logger.error(traceback.format_exc())  # Log full traceback
            print(colored(f"Error: Failed to list entries: {e}", 'red'))
            return []

    def delete_entry(self, index: int) -> None:
        """
        Deletes a password entry based on the provided index.

        :param index: The index number of the password entry to delete.
        """
        try:
            data = self.encryption_manager.load_json_data()
            if 'passwords' in data and str(index) in data['passwords']:
                del data['passwords'][str(index)]
                logger.debug(f"Deleted entry at index {index}.")
                self.encryption_manager.save_json_data(data)
                self.update_checksum()
                self.backup_index_file()
                logger.info(f"Entry at index {index} deleted successfully.")
                print(colored(f"[+] Entry at index {index} deleted successfully.", 'green'))
            else:
                logger.warning(f"No entry found at index {index}. Cannot delete non-existent entry.")
                print(colored(f"Warning: No entry found at index {index}. Cannot delete non-existent entry.", 'yellow'))

        except Exception as e:
            logger.error(f"Failed to delete entry at index {index}: {e}")
            logger.error(traceback.format_exc())  # Log full traceback
            print(colored(f"Error: Failed to delete entry at index {index}: {e}", 'red'))

    def update_checksum(self) -> None:
        """
        Updates the checksum file for the password database to ensure data integrity.
        """
        try:
            data = self.encryption_manager.load_json_data()
            json_content = json.dumps(data, indent=4)
            checksum = hashlib.sha256(json_content.encode('utf-8')).hexdigest()

            with open(DATA_CHECKSUM_FILE, 'w') as f:
                f.write(checksum)

            logger.debug(f"Checksum updated and written to '{DATA_CHECKSUM_FILE}'.")
            print(colored(f"[+] Checksum updated successfully.", 'green'))

        except Exception as e:
            logger.error(f"Failed to update checksum: {e}")
            logger.error(traceback.format_exc())  # Log full traceback
            print(colored(f"Error: Failed to update checksum: {e}", 'red'))

    def backup_index_file(self) -> None:
        """
        Creates a backup of the encrypted JSON index file to prevent data loss.
        """
        try:
            if not os.path.exists(INDEX_FILE):
                logger.warning(f"Index file '{INDEX_FILE}' does not exist. No backup created.")
                return

            timestamp = int(time.time())
            backup_filename = f'passwords_db_backup_{timestamp}.json.enc'
            backup_path = os.path.join(os.path.dirname(INDEX_FILE), backup_filename)

            with open(INDEX_FILE, 'rb') as original_file, open(backup_path, 'wb') as backup_file:
                shutil.copyfileobj(original_file, backup_file)

            logger.debug(f"Backup created at '{backup_path}'.")
            print(colored(f"[+] Backup created at '{backup_path}'.", 'green'))

        except Exception as e:
            logger.error(f"Failed to create backup: {e}")
            logger.error(traceback.format_exc())  # Log full traceback
            print(colored(f"Warning: Failed to create backup: {e}", 'yellow'))

    def restore_from_backup(self, backup_path: str) -> None:
        """
        Restores the index file from a specified backup file.

        :param backup_path: The file path of the backup to restore from.
        """
        try:
            if not os.path.exists(backup_path):
                logger.error(f"Backup file '{backup_path}' does not exist.")
                print(colored(f"Error: Backup file '{backup_path}' does not exist.", 'red'))
                return

            with open(backup_path, 'rb') as backup_file, open(INDEX_FILE, 'wb') as index_file:
                shutil.copyfileobj(backup_file, index_file)

            logger.debug(f"Index file restored from backup '{backup_path}'.")
            print(colored(f"[+] Index file restored from backup '{backup_path}'.", 'green'))

            self.update_checksum()

        except Exception as e:
            logger.error(f"Failed to restore from backup '{backup_path}': {e}")
            logger.error(traceback.format_exc())  # Log full traceback
            print(colored(f"Error: Failed to restore from backup '{backup_path}': {e}", 'red'))

    def list_all_entries(self) -> None:
        """
        Displays all password entries in a formatted manner.
        """
        try:
            entries = self.list_entries()
            if not entries:
                print(colored("No entries to display.", 'yellow'))
                return

            print(colored("\n[+] Listing All Password Entries:\n", 'green'))
            for entry in entries:
                index, website, username, url, blacklisted = entry
                print(colored(f"Index: {index}", 'cyan'))
                print(colored(f"  Website: {website}", 'cyan'))
                print(colored(f"  Username: {username or 'N/A'}", 'cyan'))
                print(colored(f"  URL: {url or 'N/A'}", 'cyan'))
                print(colored(f"  Blacklisted: {'Yes' if blacklisted else 'No'}", 'cyan'))
                print("-" * 40)

        except Exception as e:
            logger.error(f"Failed to list all entries: {e}")
            logger.error(traceback.format_exc())  # Log full traceback
            print(colored(f"Error: Failed to list all entries: {e}", 'red'))
            return

# Example usage (this part should be removed or commented out when integrating into the larger application)
if __name__ == "__main__":
    from password_manager.encryption import EncryptionManager  # Ensure this import is correct based on your project structure

    # Initialize EncryptionManager with a dummy key for demonstration purposes
    # Replace 'your-fernet-key' with your actual Fernet key
    try:
        dummy_key = Fernet.generate_key()
        encryption_manager = EncryptionManager(dummy_key)
    except Exception as e:
        logger.error(f"Failed to initialize EncryptionManager: {e}")
        print(colored(f"Error: Failed to initialize EncryptionManager: {e}", 'red'))
        sys.exit(1)

    # Initialize EntryManager
    try:
        entry_manager = EntryManager(encryption_manager)
    except Exception as e:
        logger.error(f"Failed to initialize EntryManager: {e}")
        print(colored(f"Error: Failed to initialize EntryManager: {e}", 'red'))
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
