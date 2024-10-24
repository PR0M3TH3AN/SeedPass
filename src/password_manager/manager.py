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
from utils.password_prompt import prompt_for_password, prompt_existing_password, confirm_action

from constants import (
    APP_DIR,
    INDEX_FILE,
    PARENT_SEED_FILE,
    DATA_CHECKSUM_FILE,
    SCRIPT_CHECKSUM_FILE,
    MIN_PASSWORD_LENGTH,
    MAX_PASSWORD_LENGTH,
    DEFAULT_PASSWORD_LENGTH,
    HASHED_PASSWORD_FILE,  # Ensure this constant is defined in constants.py
    DEFAULT_SEED_BACKUP_FILENAME
)

import traceback  # Added for exception traceback logging
import bcrypt  # Ensure bcrypt is installed in your environment
from pathlib import Path  # Required for handling file paths

from bip85.bip85 import BIP85
from bip_utils import Bip39SeedGenerator, Bip39MnemonicGenerator, Bip39Languages

# Import NostrClient from the nostr package
from nostr import NostrClient  # <-- Added import statement

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

# Initialize the logger for this module
logger = logging.getLogger(__name__)

class PasswordManager:
    """
    PasswordManager Class

    Manages the generation, encryption, and retrieval of deterministic passwords using a BIP-85 seed.
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
        self.parent_seed: Optional[str] = None  # Ensured to be a string
        self.bip85: Optional[BIP85] = None      # Added bip85 attribute

        self.setup_parent_seed()
        self.initialize_managers()

    def setup_parent_seed(self) -> None:
        """
        Sets up the parent seed by determining if an existing seed is present or if a new one needs to be created.
        """
        if os.path.exists(PARENT_SEED_FILE):
            self.handle_existing_seed()
        else:
            self.handle_new_seed_setup()

    def handle_existing_seed(self) -> None:
        """
        Handles the scenario where an existing parent seed file is found.
        Prompts the user for the master password to decrypt the seed.
        """
        password = getpass.getpass(prompt='Enter your login password: ').strip()
        try:
            # Derive encryption key from password
            key = derive_key_from_password(password)
            self.encryption_manager = EncryptionManager(key)
            self.parent_seed = self.encryption_manager.decrypt_parent_seed(PARENT_SEED_FILE)

            # Log the type and content of parent_seed
            logger.debug(f"Decrypted parent_seed: {self.parent_seed} (type: {type(self.parent_seed)})")

            # Validate the decrypted seed
            if not self.validate_bip85_seed(self.parent_seed):
                logging.error("Decrypted seed is invalid. Exiting.")
                print(colored("Error: Decrypted seed is invalid.", 'red'))
                sys.exit(1)

            self.initialize_bip85()
            logging.debug("Parent seed decrypted and validated successfully.")
        except Exception as e:
            logging.error(f"Failed to decrypt parent seed: {e}")
            logging.error(traceback.format_exc())
            print(colored(f"Error: Failed to decrypt parent seed: {e}", 'red'))
            sys.exit(1)

    def handle_new_seed_setup(self) -> None:
        """
        Handles the setup process when no existing parent seed is found.
        Asks the user whether to enter an existing BIP-85 seed or generate a new one.
        """
        print(colored("No existing seed found. Let's set up a new one!", 'yellow'))
        choice = input("Do you want to (1) Enter an existing BIP-85 seed or (2) Generate a new BIP-85 seed? (1/2): ").strip()

        if choice == '1':
            self.setup_existing_seed()
        elif choice == '2':
            self.generate_new_seed()
        else:
            print(colored("Invalid choice. Exiting.", 'red'))
            sys.exit(1)

    def setup_existing_seed(self) -> None:
        """
        Prompts the user to enter an existing BIP-85 seed and validates it.
        """
        try:
            parent_seed = getpass.getpass(prompt='Enter your 12-word BIP-85 seed: ').strip()
            if self.validate_bip85_seed(parent_seed):
                self.save_and_encrypt_seed(parent_seed)
            else:
                logging.error("Invalid BIP-85 seed phrase. Exiting.")
                sys.exit(1)
        except KeyboardInterrupt:
            logging.info("Operation cancelled by user.")
            print(colored("\nOperation cancelled by user.", 'yellow'))
            sys.exit(0)

    def generate_new_seed(self) -> None:
        """
        Generates a new BIP-85 seed, displays it to the user, and prompts for confirmation before saving.
        """
        new_seed = self.generate_bip85_seed()
        print(colored("Your new BIP-85 seed phrase is:", 'green'))
        print(colored(new_seed, 'yellow'))
        print(colored("Please write this down and keep it in a safe place!", 'red'))

        if confirm_action("Do you want to use this generated seed? (Y/N): "):
            self.save_and_encrypt_seed(new_seed)
        else:
            print(colored("Seed generation cancelled. Exiting.", 'yellow'))
            sys.exit(0)

    def validate_bip85_seed(self, seed: str) -> bool:
        """
        Validates the provided BIP-85 seed phrase.

        Parameters:
            seed (str): The seed phrase to validate.

        Returns:
            bool: True if valid, False otherwise.
        """
        try:
            words = seed.split()
            if len(words) != 12:
                return False
            # Additional validation can be added here if needed (e.g., word list checks)
            return True
        except Exception as e:
            logging.error(f"Error validating BIP-85 seed: {e}")
            return False

    def generate_bip85_seed(self) -> str:
        """
        Generates a new BIP-85 seed phrase.

        Returns:
            str: The generated 12-word mnemonic seed phrase.
        """
        try:
            master_seed = os.urandom(32)  # Generate a random 32-byte seed
            bip85 = BIP85(master_seed)
            mnemonic_obj = bip85.derive_mnemonic(app_no=39, language_code=0, words_num=12, index=0)
            mnemonic_str = mnemonic_obj.ToStr()  # Convert Bip39Mnemonic object to string
            return mnemonic_str
        except Exception as e:
            logging.error(f"Failed to generate BIP-85 seed: {e}")
            logging.error(traceback.format_exc())
            print(colored(f"Error: Failed to generate BIP-85 seed: {e}", 'red'))
            sys.exit(1)

    def save_and_encrypt_seed(self, seed: str) -> None:
        """
        Saves and encrypts the parent seed.

        Parameters:
            seed (str): The BIP-85 seed phrase to save and encrypt.
        """
        password = prompt_for_password()
        key = derive_key_from_password(password)
        self.encryption_manager = EncryptionManager(key)

        try:
            self.encryption_manager.encrypt_parent_seed(seed, PARENT_SEED_FILE)
            logging.info("Parent seed encrypted and saved successfully.")

            self.store_hashed_password(password)
            logging.info("User password hashed and stored successfully.")

            self.parent_seed = seed  # Ensure this is a string
            logger.debug(f"parent_seed set to: {self.parent_seed} (type: {type(self.parent_seed)})")

            self.initialize_bip85()
        except Exception as e:
            logging.error(f"Failed to encrypt and save parent seed: {e}")
            logging.error(traceback.format_exc())
            print(colored(f"Error: Failed to encrypt and save parent seed: {e}", 'red'))
            sys.exit(1)

    def initialize_bip85(self):
        """
        Initializes the BIP-85 generator using the parent seed.
        """
        try:
            seed_bytes = Bip39SeedGenerator(self.parent_seed).Generate()
            self.bip85 = BIP85(seed_bytes)
            logging.debug("BIP-85 initialized successfully.")
        except Exception as e:
            logging.error(f"Failed to initialize BIP-85: {e}")
            logging.error(traceback.format_exc())
            print(colored(f"Error: Failed to initialize BIP-85: {e}", 'red'))
            sys.exit(1)

    def initialize_managers(self) -> None:
        """
        Initializes the EntryManager, PasswordGenerator, and BackupManager with the EncryptionManager
        and BIP-85 instance.
        """
        try:
            self.entry_manager = EntryManager(self.encryption_manager)
            self.password_generator = PasswordGenerator(self.encryption_manager, self.parent_seed)
            self.backup_manager = BackupManager()

            # Directly pass the parent_seed string to NostrClient
            self.nostr_client = NostrClient(parent_seed=self.parent_seed)  # <-- NostrClient is now imported

            logging.debug("EntryManager, PasswordGenerator, BackupManager, and NostrClient initialized.")
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

    def handle_backup_reveal_parent_seed(self) -> None:
        """
        Handles the backup and reveal of the parent seed.
        """
        try:
            print(colored("\n=== Backup/Reveal Parent Seed ===", 'yellow'))
            print(colored("Warning: Revealing your parent seed is a highly sensitive operation.", 'red'))
            print(colored("Ensure you're in a secure, private environment and no one is watching your screen.", 'red'))
            
            # Verify user's identity with secure password verification
            password = prompt_existing_password("Enter your master password to continue: ")
            if not self.verify_password(password):
                print(colored("Incorrect password. Operation aborted.", 'red'))
                return

            # Double confirmation
            if not confirm_action("Are you absolutely sure you want to reveal your parent seed? (Y/N): "):
                print(colored("Operation cancelled by user.", 'yellow'))
                return

            # Reveal the parent seed
            print(colored("\n=== Your BIP-85 Parent Seed ===", 'green'))
            print(colored(self.parent_seed, 'yellow'))
            print(colored("\nPlease write this down and store it securely. Do not share it with anyone.", 'red'))

            # Option to save to file with default filename
            if confirm_action("Do you want to save this to an encrypted backup file? (Y/N): "):
                filename = input(f"Enter filename to save (default: {DEFAULT_SEED_BACKUP_FILENAME}): ").strip()
                filename = filename if filename else DEFAULT_SEED_BACKUP_FILENAME
                backup_path = Path(APP_DIR) / filename

                # Validate filename
                if not self.is_valid_filename(filename):
                    print(colored("Invalid filename. Operation aborted.", 'red'))
                    return

                self.encryption_manager.encrypt_parent_seed(self.parent_seed, backup_path)
                print(colored(f"Encrypted seed backup saved to '{backup_path}'. Ensure this file is stored securely.", 'green'))

        except Exception as e:
            logging.error(f"Error during parent seed backup/reveal: {e}")
            logging.error(traceback.format_exc())
            print(colored(f"Error: Failed to backup/reveal parent seed: {e}", 'red'))

    def verify_password(self, password: str) -> bool:
        """
        Verifies the provided password against the stored hashed password.

        Parameters:
            password (str): The password to verify.

        Returns:
            bool: True if the password is correct, False otherwise.
        """
        try:
            if not os.path.exists(HASHED_PASSWORD_FILE):
                logging.error("Hashed password file not found.")
                print(colored("Error: Hashed password file not found.", 'red'))
                return False
            with open(HASHED_PASSWORD_FILE, 'rb') as f:
                stored_hash = f.read()
            is_correct = bcrypt.checkpw(password.encode('utf-8'), stored_hash)
            if is_correct:
                logging.debug("Password verification successful.")
            else:
                logging.warning("Password verification failed.")
            return is_correct
        except Exception as e:
            logging.error(f"Error verifying password: {e}")
            logging.error(traceback.format_exc())
            print(colored(f"Error: Failed to verify password: {e}", 'red'))
            return False

    def is_valid_filename(self, filename: str) -> bool:
        """
        Validates the provided filename to prevent directory traversal and invalid characters.

        Parameters:
            filename (str): The filename to validate.

        Returns:
            bool: True if valid, False otherwise.
        """
        # Basic validation: filename should not contain path separators or be empty
        invalid_chars = ['/', '\\', '..']
        if any(char in filename for char in invalid_chars) or not filename:
            logging.warning(f"Invalid filename attempted: {filename}")
            return False
        return True

    def store_hashed_password(self, password: str) -> None:
        """
        Hashes and stores the user's password securely using bcrypt.
        This should be called during the initial setup.
        """
        try:
            hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            with open(HASHED_PASSWORD_FILE, 'wb') as f:
                f.write(hashed)
            # Set file permissions to read/write for the user only
            os.chmod(HASHED_PASSWORD_FILE, 0o600)
            logging.info("User password hashed and stored successfully.")
        except AttributeError:
            # If bcrypt.hashpw is not available, try using bcrypt directly
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
            with open(HASHED_PASSWORD_FILE, 'wb') as f:
                f.write(hashed)
            os.chmod(HASHED_PASSWORD_FILE, 0o600)
            logging.info("User password hashed and stored successfully (using alternative method).")
        except Exception as e:
            logging.error(f"Failed to store hashed password: {e}")
            logging.error(traceback.format_exc())
            print(colored(f"Error: Failed to store hashed password: {e}", 'red'))
            raise

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
