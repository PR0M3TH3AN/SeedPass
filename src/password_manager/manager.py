# password_manager/manager.py

"""
Password Manager Module

This module implements the PasswordManager class, which orchestrates various functionalities
of the deterministic password manager, including encryption, entry management, password
generation, backup, and checksum verification. It serves as the core interface for interacting
with the password manager functionalities.

Dependencies:
- password_manager.encryption.EncryptionManager
- password_manager.entry_management.EntryManager
- password_manager.password_generation.PasswordGenerator
- password_manager.backup.BackupManager
- utils.key_derivation.derive_key_from_parent_seed
- utils.key_derivation.derive_key_from_password
- utils.checksum.calculate_checksum
- utils.checksum.verify_checksum
- utils.password_prompt.prompt_for_password
- constants.APP_DIR
- constants.INDEX_FILE
- constants.PARENT_SEED_FILE
- constants.DATA_CHECKSUM_FILE
- constants.SCRIPT_CHECKSUM_FILE
- constants.MIN_PASSWORD_LENGTH
- constants.MAX_PASSWORD_LENGTH
- constants.DEFAULT_PASSWORD_LENGTH
- colorama.Fore
- termcolor.colored
- logging
- json
- sys
- os
- getpass

Ensure that all dependencies are installed and properly configured in your environment.
"""

# password_manager/manager.py

"""
Password Manager Module

This module implements the PasswordManager class, which orchestrates various functionalities
of the deterministic password manager, including encryption, entry management, password
generation, backup, and checksum verification. It serves as the core interface for interacting
with the password manager functionalities.
"""

import sys
import json
import logging
import getpass
import os
from typing import Optional

from colorama import Fore
from termcolor import colored

from password_manager.encryption import EncryptionManager
from password_manager.entry_management import EntryManager
from password_manager.password_generation import PasswordGenerator
from password_manager.backup import BackupManager
from utils.key_derivation import derive_key_from_parent_seed, derive_key_from_password
from utils.checksum import calculate_checksum, verify_checksum
from utils.password_prompt import prompt_for_password

from constants import (
    APP_DIR,
    INDEX_FILE,
    PARENT_SEED_FILE,
    DATA_CHECKSUM_FILE,
    SCRIPT_CHECKSUM_FILE,
    MIN_PASSWORD_LENGTH,
    MAX_PASSWORD_LENGTH,
    DEFAULT_PASSWORD_LENGTH
)

import traceback  # Added for exception traceback logging

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
        f_handler = logging.FileHandler(os.path.join('logs', 'password_manager.log'))

        # Set levels: only errors and critical messages will be shown in the console
        c_handler.setLevel(logging.ERROR)
        f_handler.setLevel(logging.DEBUG)

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

class PasswordManager:
    """
    PasswordManager Class

    Manages the generation, encryption, and retrieval of deterministic passwords using a BIP-39 seed.
    It handles file encryption/decryption, password generation, entry management, backups, and checksum
    verification, ensuring the integrity and confidentiality of the stored password database.
    """

    def __init__(self):
        """
        Initializes the PasswordManager by setting up encryption, loading or setting up the parent seed,
        and initializing other components like EntryManager, PasswordGenerator, and BackupManager.
        """
        self.encryption_manager: Optional[EncryptionManager] = None
        self.entry_manager: Optional[EntryManager] = None
        self.password_generator: Optional[PasswordGenerator] = None
        self.backup_manager: Optional[BackupManager] = None
        self.parent_seed: Optional[str] = None  # Added parent_seed attribute

        self.setup_parent_seed()
        self.initialize_managers()

    def setup_parent_seed(self) -> None:
        if os.path.exists(PARENT_SEED_FILE):
            # Parent seed file exists, prompt for password to decrypt
            password = getpass.getpass(prompt='Enter your login password: ').strip()
            try:
                # Derive encryption key from password
                key = derive_key_from_password(password)
                self.encryption_manager = EncryptionManager(key)
                self.parent_seed = self.encryption_manager.decrypt_parent_seed(PARENT_SEED_FILE)
                
                # **Add validation for the decrypted seed**
                if not self.validate_seed_phrase(self.parent_seed):
                    logging.error("Decrypted seed is invalid. Exiting.")
                    print(colored("Error: Decrypted seed is invalid.", 'red'))
                    sys.exit(1)
                
                logging.debug("Parent seed decrypted and validated successfully.")
            except Exception as e:
                logging.error(f"Failed to decrypt parent seed: {e}")
                logging.error(traceback.format_exc())
                print(colored(f"Error: Failed to decrypt parent seed: {e}", 'red'))
                sys.exit(1)
        else:
            # First-time setup: prompt for parent seed and password
            try:
                parent_seed = getpass.getpass(prompt='Enter your 12-word parent seed: ').strip()
                # Validate parent seed (basic validation)
                parent_seed = self.basic_validate_seed_phrase(parent_seed)
                if not parent_seed:
                    logging.error("Invalid seed phrase. Exiting.")
                    sys.exit(1)
            except KeyboardInterrupt:
                logging.info("Operation cancelled by user.")
                print(colored("\nOperation cancelled by user.", 'yellow'))
                sys.exit(0)
            
            # Prompt for password
            password = prompt_for_password()
            
            # Derive encryption key from password
            key = derive_key_from_password(password)
            self.encryption_manager = EncryptionManager(key)
            
            # Encrypt and save the parent seed
            try:
                self.encryption_manager.encrypt_parent_seed(parent_seed, PARENT_SEED_FILE)
                logging.info("Parent seed encrypted and saved successfully.")
            except Exception as e:
                logging.error(f"Failed to encrypt and save parent seed: {e}")
                logging.error(traceback.format_exc())
                print(colored(f"Error: Failed to encrypt and save parent seed: {e}", 'red'))
                sys.exit(1)
            
            self.parent_seed = parent_seed

    def basic_validate_seed_phrase(self, seed_phrase: str) -> Optional[str]:
        """
        Performs basic validation on the seed phrase without relying on EncryptionManager.

        Parameters:
            seed_phrase (str): The seed phrase to validate.

        Returns:
            Optional[str]: The validated seed phrase or None if invalid.
        """
        try:
            words = seed_phrase.split()
            if len(words) != 12:
                logging.error("Seed phrase must contain exactly 12 words.")
                print(colored("Error: Seed phrase must contain exactly 12 words.", 'red'))
                return None
            # Additional basic validations can be added here (e.g., word list checks)
            logging.debug("Seed phrase validated successfully.")
            return seed_phrase
        except Exception as e:
            logging.error(f"Error during basic seed validation: {e}")
            logging.error(traceback.format_exc())
            print(colored(f"Error: {e}", 'red'))
            return None

    def validate_seed_phrase(self, seed_phrase: str) -> Optional[str]:
        """
        Validates the seed phrase using the EncryptionManager if available,
        otherwise performs basic validation.

        Parameters:
            seed_phrase (str): The seed phrase to validate.

        Returns:
            Optional[str]: The validated seed phrase or None if invalid.
        """
        try:
            if self.encryption_manager:
                # Use EncryptionManager to validate seed
                if self.encryption_manager.validate_seed(seed_phrase):
                    logging.debug("Seed phrase validated successfully using EncryptionManager.")
                    return seed_phrase
                else:
                    logging.error("Invalid seed phrase.")
                    print(colored("Error: Invalid seed phrase.", 'red'))
                    return None
            else:
                # Perform basic validation
                return self.basic_validate_seed_phrase(seed_phrase)
        except Exception as e:
            logging.error(f"Error validating seed phrase: {e}")
            logging.error(traceback.format_exc())
            print(colored(f"Error: Failed to validate seed phrase: {e}", 'red'))
            return None

    def initialize_managers(self) -> None:
        """
        Initializes the EntryManager, PasswordGenerator, and BackupManager with the EncryptionManager
        and parent seed.
        """
        try:
            self.entry_manager = EntryManager(self.encryption_manager)
            self.password_generator = PasswordGenerator(self.encryption_manager, self.parent_seed)
            self.backup_manager = BackupManager()
            logging.debug("EntryManager, PasswordGenerator, and BackupManager initialized.")
        except Exception as e:
            logging.error(f"Failed to initialize managers: {e}")
            logging.error(traceback.format_exc())
            print(colored(f"Error: Failed to initialize managers: {e}", 'red'))
            sys.exit(1)

    def handle_generate_password(self) -> None:
        try:
            website_name = input('Enter the website name: ').strip()
            if not website_name:
                print(colored("Error: Website name cannot be empty.", 'red'))
                return

            username = input('Enter the username (optional): ').strip()
            url = input('Enter the URL (optional): ').strip()

            length_input = input(f'Enter desired password length (default {DEFAULT_PASSWORD_LENGTH}): ').strip()
            length = DEFAULT_PASSWORD_LENGTH
            if length_input:
                if not length_input.isdigit():
                    print(colored("Error: Password length must be a number.", 'red'))
                    return
                length = int(length_input)
                if not (MIN_PASSWORD_LENGTH <= length <= MAX_PASSWORD_LENGTH):
                    print(colored(f"Error: Password length must be between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH}.", 'red'))
                    return

            # Add the entry to the index and get the assigned index
            index = self.entry_manager.add_entry(website_name, length, username, url, blacklisted=False)

            # Generate the password using the assigned index
            password = self.password_generator.generate_password(length, index)

            # Provide user feedback
            print(colored(f"\n[+] Password generated and indexed with ID {index}.\n", 'green'))
            print(colored(f"Password for {website_name}: {password}\n", 'yellow'))

        except Exception as e:
            logging.error(f"Error during password generation: {e}")
            logging.error(traceback.format_exc())
            print(colored(f"Error: Failed to generate password: {e}", 'red'))

    def handle_retrieve_password(self) -> None:
        """
        Handles retrieving a password from the index by prompting the user for the index number
        and displaying the corresponding password and associated details.
        """
        try:
            index_input = input('Enter the index number of the password to retrieve: ').strip()
            if not index_input.isdigit():
                print(colored("Error: Index must be a number.", 'red'))
                return
            index = int(index_input)

            # Retrieve entry details
            entry = self.entry_manager.retrieve_entry(index)
            if not entry:
                return

            # Display entry details
            website_name = entry.get('website')
            length = entry.get('length')
            username = entry.get('username')
            url = entry.get('url')
            blacklisted = entry.get('blacklisted')

            print(colored(f"Retrieving password for '{website_name}' with length {length}.", 'cyan'))
            if username:
                print(colored(f"Username: {username}", 'cyan'))
            if url:
                print(colored(f"URL: {url}", 'cyan'))
            if blacklisted:
                print(colored(f"Warning: This password is blacklisted and should not be used.", 'red'))

            # Generate the password
            password = self.password_generator.generate_password(length, index)

            # Display the password and associated details
            if password:
                print(colored(f"\n[+] Retrieved Password for {website_name}:\n", 'green'))
                print(colored(f"Password: {password}", 'yellow'))
                print(colored(f"Associated Username: {username or 'N/A'}", 'cyan'))
                print(colored(f"Associated URL: {url or 'N/A'}", 'cyan'))
                print(colored(f"Blacklist Status: {'Blacklisted' if blacklisted else 'Not Blacklisted'}", 'cyan'))
            else:
                print(colored("Error: Failed to retrieve the password.", 'red'))
        except Exception as e:
            logging.error(f"Error during password retrieval: {e}")
            logging.error(traceback.format_exc())
            print(colored(f"Error: Failed to retrieve password: {e}", 'red'))

    def handle_modify_entry(self) -> None:
        """
        Handles modifying an existing password entry by prompting the user for the index number
        and new details to update.
        """
        try:
            index_input = input('Enter the index number of the entry to modify: ').strip()
            if not index_input.isdigit():
                print(colored("Error: Index must be a number.", 'red'))
                return
            index = int(index_input)

            # Retrieve existing entry
            entry = self.entry_manager.retrieve_entry(index)
            if not entry:
                return

            website_name = entry.get('website')
            length = entry.get('length')
            username = entry.get('username')
            url = entry.get('url')
            blacklisted = entry.get('blacklisted')

            # Display current values
            print(colored(f"Modifying entry for '{website_name}' (Index: {index}):", 'cyan'))
            print(colored(f"Current Username: {username or 'N/A'}", 'cyan'))
            print(colored(f"Current URL: {url or 'N/A'}", 'cyan'))
            print(colored(f"Current Blacklist Status: {'Blacklisted' if blacklisted else 'Not Blacklisted'}", 'cyan'))

            # Prompt for new values (optional)
            new_username = input(f'Enter new username (leave blank to keep "{username or "N/A"}"): ').strip() or username
            new_url = input(f'Enter new URL (leave blank to keep "{url or "N/A"}"): ').strip() or url
            blacklist_input = input(f'Is this password blacklisted? (Y/N, current: {"Y" if blacklisted else "N"}): ').strip().lower()
            if blacklist_input == '':
                new_blacklisted = blacklisted
            elif blacklist_input == 'y':
                new_blacklisted = True
            elif blacklist_input == 'n':
                new_blacklisted = False
            else:
                print(colored("Invalid input for blacklist status. Keeping the current status.", 'yellow'))
                new_blacklisted = blacklisted

            # Update the entry
            self.entry_manager.modify_entry(index, new_username, new_url, new_blacklisted)

            print(colored(f"Entry updated successfully for index {index}.", 'green'))

        except Exception as e:
            logging.error(f"Error during modifying entry: {e}")
            logging.error(traceback.format_exc())
            print(colored(f"Error: Failed to modify entry: {e}", 'red'))

    def handle_verify_checksum(self) -> None:
        """
        Handles verifying the script's checksum against the stored checksum to ensure integrity.
        """
        try:
            current_checksum = calculate_checksum(__file__)
            if verify_checksum(current_checksum, SCRIPT_CHECKSUM_FILE):
                print(colored("Checksum verification passed.", 'green'))
                logging.info("Checksum verification passed.")
            else:
                print(colored("Checksum verification failed. The script may have been modified.", 'red'))
                logging.error("Checksum verification failed.")
        except Exception as e:
            logging.error(f"Error during checksum verification: {e}")
            logging.error(traceback.format_exc())
            print(colored(f"Error: Failed to verify checksum: {e}", 'red'))

    def get_encrypted_data(self) -> Optional[bytes]:
        """
        Retrieves the encrypted password index data.

        :return: The encrypted data as bytes, or None if retrieval fails.
        """
        try:
            encrypted_data = self.encryption_manager.get_encrypted_index()
            if encrypted_data:
                logging.debug("Encrypted index data retrieved successfully.")
                return encrypted_data
            else:
                logging.error("Failed to retrieve encrypted index data.")
                print(colored("Error: Failed to retrieve encrypted index data.", 'red'))
                return None
        except Exception as e:
            logging.error(f"Error retrieving encrypted data: {e}")
            logging.error(traceback.format_exc())
            print(colored(f"Error: Failed to retrieve encrypted data: {e}", 'red'))
            return None

    def decrypt_and_save_index_from_nostr(self, encrypted_data: bytes) -> None:
        """
        Decrypts the encrypted data retrieved from Nostr and updates the local index.

        :param encrypted_data: The encrypted data retrieved from Nostr.
        """
        try:
            self.encryption_manager.decrypt_and_save_index_from_nostr(encrypted_data)
            logging.info("Index file updated from Nostr successfully.")
            print(colored("Index file updated from Nostr successfully.", 'green'))
        except Exception as e:
            logging.error(f"Failed to decrypt and save data from Nostr: {e}")
            logging.error(traceback.format_exc())
            print(colored(f"Error: Failed to decrypt and save data from Nostr: {e}", 'red'))

    def backup_database(self) -> None:
        """
        Creates a backup of the encrypted JSON index file.
        """
        try:
            self.backup_manager.create_backup()
            print(colored("Backup created successfully.", 'green'))
        except Exception as e:
            logging.error(f"Failed to create backup: {e}")
            logging.error(traceback.format_exc())
            print(colored(f"Error: Failed to create backup: {e}", 'red'))

    def restore_database(self) -> None:
        """
        Restores the encrypted JSON index file from the latest backup.
        """
        try:
            self.backup_manager.restore_latest_backup()
            print(colored("Database restored from the latest backup successfully.", 'green'))
        except Exception as e:
            logging.error(f"Failed to restore backup: {e}")
            logging.error(traceback.format_exc())
            print(colored(f"Error: Failed to restore backup: {e}", 'red'))

    # Additional methods can be added here as needed

# Example usage (this part should be removed or commented out when integrating into the larger application)
if __name__ == "__main__":
    from nostr.client import NostrClient  # Ensure this import is correct based on your project structure

    # Initialize PasswordManager
    manager = PasswordManager()

    # Initialize NostrClient with the parent seed from PasswordManager
    nostr_client = NostrClient(parent_seed=manager.parent_seed)

    # Example operations
    # These would typically be triggered by user interactions, e.g., via a CLI menu
    # manager.handle_generate_password()
    # manager.handle_retrieve_password()
    # manager.handle_modify_entry()
    # manager.handle_verify_checksum()
    # manager.post_to_nostr(nostr_client)
    # manager.retrieve_from_nostr(nostr_client)
    # manager.backup_database()
    # manager.restore_database()
