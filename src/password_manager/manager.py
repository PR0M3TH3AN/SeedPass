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
import shutil
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
    PARENT_SEED_FILE,
    SCRIPT_CHECKSUM_FILE,
    MIN_PASSWORD_LENGTH,
    MAX_PASSWORD_LENGTH,
    DEFAULT_PASSWORD_LENGTH,
    DEFAULT_SEED_BACKUP_FILENAME
)

import traceback  
import bcrypt  
from pathlib import Path  

from local_bip85.bip85 import BIP85
from bip_utils import Bip39SeedGenerator, Bip39MnemonicGenerator, Bip39Languages

from utils.fingerprint_manager import FingerprintManager

# Import NostrClient
from nostr.client import NostrClient 

# Instantiate the logger
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
        and initializing other components like EntryManager, PasswordGenerator, BackupManager, and FingerprintManager.
        """
        self.encryption_manager: Optional[EncryptionManager] = None
        self.entry_manager: Optional[EntryManager] = None
        self.password_generator: Optional[PasswordGenerator] = None
        self.backup_manager: Optional[BackupManager] = None
        self.fingerprint_manager: Optional[FingerprintManager] = None
        self.parent_seed: Optional[str] = None
        self.bip85: Optional[BIP85] = None
        self.nostr_client: Optional[NostrClient] = None

        # Initialize the fingerprint manager first
        self.initialize_fingerprint_manager()

        # Ensure a parent seed is set up before accessing the fingerprint directory
        self.setup_parent_seed()

        # Set the current fingerprint directory
        self.fingerprint_dir = self.fingerprint_manager.get_current_fingerprint_dir()

    def initialize_fingerprint_manager(self):
        """
        Initializes the FingerprintManager.
        """
        try:
            self.fingerprint_manager = FingerprintManager(APP_DIR)
            logger.debug("FingerprintManager initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to initialize FingerprintManager: {e}")
            logger.error(traceback.format_exc())
            print(colored(f"Error: Failed to initialize FingerprintManager: {e}", 'red'))
            sys.exit(1)

    def setup_parent_seed(self) -> None:
        """
        Sets up the parent seed by determining if existing fingerprints are present or if a new one needs to be created.
        """
        fingerprints = self.fingerprint_manager.list_fingerprints()
        if fingerprints:
            # There are existing fingerprints
            self.select_or_add_fingerprint()
        else:
            # No existing fingerprints, proceed to set up new seed
            self.handle_new_seed_setup()

    def select_or_add_fingerprint(self):
        """
        Prompts the user to select an existing fingerprint or add a new one.
        """
        try:
            print(colored("\nAvailable Fingerprints:", 'cyan'))
            fingerprints = self.fingerprint_manager.list_fingerprints()
            for idx, fp in enumerate(fingerprints, start=1):
                print(colored(f"{idx}. {fp}", 'cyan'))

            print(colored(f"{len(fingerprints)+1}. Add a new fingerprint", 'cyan'))

            choice = input("Select a fingerprint by number: ").strip()
            if not choice.isdigit() or not (1 <= int(choice) <= len(fingerprints)+1):
                print(colored("Invalid selection. Exiting.", 'red'))
                sys.exit(1)

            choice = int(choice)
            if choice == len(fingerprints)+1:
                # Add a new fingerprint
                self.add_new_fingerprint()
            else:
                # Select existing fingerprint
                selected_fingerprint = fingerprints[choice-1]
                self.select_fingerprint(selected_fingerprint)

        except Exception as e:
            logger.error(f"Error during fingerprint selection: {e}")
            logger.error(traceback.format_exc())
            print(colored(f"Error: Failed to select fingerprint: {e}", 'red'))
            sys.exit(1)

    def add_new_fingerprint(self):
        """
        Adds a new fingerprint by generating it from a seed phrase.
        """
        try:
            choice = input("Do you want to (1) Enter an existing seed or (2) Generate a new seed? (1/2): ").strip()
            if choice == '1':
                fingerprint = self.setup_existing_seed()
            elif choice == '2':
                fingerprint = self.generate_new_seed()
            else:
                print(colored("Invalid choice. Exiting.", 'red'))
                sys.exit(1)

            # Set current_fingerprint in FingerprintManager only
            self.fingerprint_manager.current_fingerprint = fingerprint
            print(colored(f"New fingerprint '{fingerprint}' added and set as current.", 'green'))

        except Exception as e:
            logger.error(f"Error adding new fingerprint: {e}")
            logger.error(traceback.format_exc())
            print(colored(f"Error: Failed to add new fingerprint: {e}", 'red'))
            sys.exit(1)

    def select_fingerprint(self, fingerprint: str) -> None:
        if self.fingerprint_manager.select_fingerprint(fingerprint):
            self.current_fingerprint = fingerprint  # Add this line
            self.fingerprint_dir = self.fingerprint_manager.get_current_fingerprint_dir()
            if not self.fingerprint_dir:
                print(colored(f"Error: Fingerprint directory for {fingerprint} not found.", 'red'))
                sys.exit(1)
            # Setup the encryption manager and load parent seed
            self.setup_encryption_manager(self.fingerprint_dir)
            self.load_parent_seed(self.fingerprint_dir)
            # Initialize BIP85 and other managers
            self.initialize_bip85()
            self.initialize_managers()
            print(colored(f"Fingerprint {fingerprint} selected and managers initialized.", 'green'))
        else:
            print(colored(f"Error: Fingerprint {fingerprint} not found.", 'red'))
            sys.exit(1)

    def setup_encryption_manager(self, fingerprint_dir: Path, password: Optional[str] = None):
        """
        Sets up the EncryptionManager for the selected fingerprint.

        Parameters:
            fingerprint_dir (Path): The directory corresponding to the fingerprint.
            password (Optional[str]): The user's master password.
        """
        try:
            # Prompt for password if not provided
            if password is None:
                password = prompt_existing_password("Enter your master password: ")
            # Derive key from password
            key = derive_key_from_password(password)
            self.encryption_manager = EncryptionManager(key, fingerprint_dir)
            logger.debug("EncryptionManager set up successfully for selected fingerprint.")

            # Verify the password
            self.fingerprint_dir = fingerprint_dir  # Ensure self.fingerprint_dir is set
            if not self.verify_password(password):
                print(colored("Invalid password. Exiting.", 'red'))
                sys.exit(1)
        except Exception as e:
            logger.error(f"Failed to set up EncryptionManager: {e}")
            logger.error(traceback.format_exc())
            print(colored(f"Error: Failed to set up encryption: {e}", 'red'))
            sys.exit(1)

    def load_parent_seed(self, fingerprint_dir: Path):
        """
        Loads and decrypts the parent seed from the fingerprint directory.

        Parameters:
            fingerprint_dir (Path): The directory corresponding to the fingerprint.
        """
        try:
            self.parent_seed = self.encryption_manager.decrypt_parent_seed()
            logger.debug(f"Parent seed loaded for fingerprint {self.current_fingerprint}.")
            # Initialize BIP85 with the parent seed
            seed_bytes = Bip39SeedGenerator(self.parent_seed).Generate()
            self.bip85 = BIP85(seed_bytes)
            logger.debug("BIP-85 initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to load parent seed: {e}")
            logger.error(traceback.format_exc())
            print(colored(f"Error: Failed to load parent seed: {e}", 'red'))
            sys.exit(1)

    def handle_switch_fingerprint(self) -> bool:
        """
        Handles switching to a different fingerprint.

        Returns:
            bool: True if switch was successful, False otherwise.
        """
        try:
            print(colored("\nAvailable Fingerprints:", 'cyan'))
            fingerprints = self.fingerprint_manager.list_fingerprints()
            for idx, fp in enumerate(fingerprints, start=1):
                print(colored(f"{idx}. {fp}", 'cyan'))

            choice = input("Select a fingerprint by number to switch: ").strip()
            if not choice.isdigit() or not (1 <= int(choice) <= len(fingerprints)):
                print(colored("Invalid selection. Returning to main menu.", 'red'))
                return False  # Return False to indicate failure

            selected_fingerprint = fingerprints[int(choice) - 1]
            self.fingerprint_manager.current_fingerprint = selected_fingerprint
            self.current_fingerprint = selected_fingerprint

            # Update fingerprint directory
            self.fingerprint_dir = self.fingerprint_manager.get_current_fingerprint_dir()
            if not self.fingerprint_dir:
                print(colored(f"Error: Fingerprint directory for {selected_fingerprint} not found.", 'red'))
                return False  # Return False to indicate failure

            # Prompt for master password for the selected fingerprint
            password = prompt_existing_password("Enter your master password: ")

            # Set up the encryption manager with the new password and fingerprint directory
            self.setup_encryption_manager(self.fingerprint_dir, password)

            # Load the parent seed for the selected fingerprint
            self.load_parent_seed(self.fingerprint_dir)

            # Initialize BIP85 and other managers
            self.initialize_bip85()
            self.initialize_managers()
            print(colored(f"Switched to fingerprint {selected_fingerprint}.", 'green'))

            # Re-initialize NostrClient with the new fingerprint
            try:
                self.nostr_client = NostrClient(
                    encryption_manager=self.encryption_manager,
                    fingerprint=self.current_fingerprint
                )
                logging.info(f"NostrClient re-initialized with fingerprint {self.current_fingerprint}.")
            except Exception as e:
                logging.error(f"Failed to re-initialize NostrClient: {e}")
                print(colored(f"Error: Failed to re-initialize NostrClient: {e}", 'red'))
                return False

            return True  # Return True to indicate success

        except Exception as e:
            logging.error(f"Error during fingerprint switching: {e}")
            logging.error(traceback.format_exc())
            print(colored(f"Error: Failed to switch fingerprints: {e}", 'red'))
            return False  # Return False to indicate failure

    def handle_existing_seed(self) -> None:
        """
        Handles the scenario where an existing parent seed file is found.
        Prompts the user for the master password to decrypt the seed.
        """
        try:
            # Prompt for password
            password = getpass.getpass(prompt='Enter your login password: ').strip()
            
            # Derive encryption key from password
            key = derive_key_from_password(password)
            
            # Initialize FingerprintManager if not already initialized
            if not self.fingerprint_manager:
                self.initialize_fingerprint_manager()
            
            # Prompt the user to select an existing fingerprint
            fingerprints = self.fingerprint_manager.list_fingerprints()
            if not fingerprints:
                print(colored("No fingerprints available. Please add a fingerprint first.", 'red'))
                sys.exit(1)
            
            print(colored("Available Fingerprints:", 'cyan'))
            for idx, fp in enumerate(fingerprints, start=1):
                print(colored(f"{idx}. {fp}", 'cyan'))
            
            choice = input("Select a fingerprint by number: ").strip()
            if not choice.isdigit() or not (1 <= int(choice) <= len(fingerprints)):
                print(colored("Invalid selection. Exiting.", 'red'))
                sys.exit(1)
            
            selected_fingerprint = fingerprints[int(choice)-1]
            self.current_fingerprint = selected_fingerprint
            fingerprint_dir = self.fingerprint_manager.get_fingerprint_directory(selected_fingerprint)
            if not fingerprint_dir:
                print(colored("Error: Fingerprint directory not found.", 'red'))
                sys.exit(1)
            
            # Initialize EncryptionManager with key and fingerprint_dir
            self.encryption_manager = EncryptionManager(key, fingerprint_dir)
            self.parent_seed = self.encryption_manager.decrypt_parent_seed()
            
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

    def setup_existing_seed(self) -> Optional[str]:
        """
        Prompts the user to enter an existing BIP-85 seed and validates it.
        
        Returns:
            Optional[str]: The fingerprint if setup is successful, None otherwise.
        """
        try:
            parent_seed = getpass.getpass(prompt='Enter your 12-word BIP-85 seed: ').strip()
            if self.validate_bip85_seed(parent_seed):
                # Add a fingerprint using the existing seed
                fingerprint = self.fingerprint_manager.add_fingerprint(parent_seed)
                if not fingerprint:
                    print(colored("Error: Failed to generate fingerprint for the provided seed.", 'red'))
                    sys.exit(1)

                fingerprint_dir = self.fingerprint_manager.get_fingerprint_directory(fingerprint)
                if not fingerprint_dir:
                    print(colored("Error: Failed to retrieve fingerprint directory.", 'red'))
                    sys.exit(1)

                # Set the current fingerprint in both PasswordManager and FingerprintManager
                self.current_fingerprint = fingerprint
                self.fingerprint_manager.current_fingerprint = fingerprint
                self.fingerprint_dir = fingerprint_dir
                logging.info(f"Current fingerprint set to {fingerprint}")

                # Initialize EncryptionManager with key and fingerprint_dir
                password = prompt_for_password()
                key = derive_key_from_password(password)
                self.encryption_manager = EncryptionManager(key, fingerprint_dir)

                # Encrypt and save the parent seed
                self.encryption_manager.encrypt_parent_seed(parent_seed)
                logging.info("Parent seed encrypted and saved successfully.")

                # Store the hashed password
                self.store_hashed_password(password)
                logging.info("User password hashed and stored successfully.")

                self.parent_seed = parent_seed  # Ensure this is a string
                logger.debug(f"parent_seed set to: {self.parent_seed} (type: {type(self.parent_seed)})")

                self.initialize_bip85()
                self.initialize_managers()
                return fingerprint  # Return the generated or added fingerprint
            else:
                logging.error("Invalid BIP-85 seed phrase. Exiting.")
                print(colored("Error: Invalid BIP-85 seed phrase.", 'red'))
                sys.exit(1)
        except KeyboardInterrupt:
            logging.info("Operation cancelled by user.")
            print(colored("\nOperation cancelled by user.", 'yellow'))
            sys.exit(0)

    def generate_new_seed(self) -> Optional[str]:
        """
        Generates a new BIP-85 seed, displays it to the user, and prompts for confirmation before saving.

        Returns:
            Optional[str]: The fingerprint if generation is successful, None otherwise.
        """
        new_seed = self.generate_bip85_seed()
        print(colored("Your new BIP-85 seed phrase is:", 'green'))
        print(colored(new_seed, 'yellow'))
        print(colored("Please write this down and keep it in a safe place!", 'red'))

        if confirm_action("Do you want to use this generated seed? (Y/N): "):
            # Add a new fingerprint using the generated seed
            fingerprint = self.fingerprint_manager.add_fingerprint(new_seed)
            if not fingerprint:
                print(colored("Error: Failed to generate fingerprint for the new seed.", 'red'))
                sys.exit(1)

            fingerprint_dir = self.fingerprint_manager.get_fingerprint_directory(fingerprint)
            if not fingerprint_dir:
                print(colored("Error: Failed to retrieve fingerprint directory.", 'red'))
                sys.exit(1)

            # Set the current fingerprint in both PasswordManager and FingerprintManager
            self.current_fingerprint = fingerprint
            self.fingerprint_manager.current_fingerprint = fingerprint
            logging.info(f"Current fingerprint set to {fingerprint}")

            # Now, save and encrypt the seed with the fingerprint_dir
            self.save_and_encrypt_seed(new_seed, fingerprint_dir)

            return fingerprint  # Return the generated fingerprint
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
            mnemonic_obj = bip85.derive_mnemonic(index=0, words_num=12)
            mnemonic_str = mnemonic_obj.ToStr()  # Convert Bip39Mnemonic object to string
            return mnemonic_str
        except Exception as e:
            logging.error(f"Failed to generate BIP-85 seed: {e}")
            logging.error(traceback.format_exc())
            print(colored(f"Error: Failed to generate BIP-85 seed: {e}", 'red'))
            sys.exit(1)

    def save_and_encrypt_seed(self, seed: str, fingerprint_dir: Path) -> None:
        """
        Saves and encrypts the parent seed.

        Parameters:
            seed (str): The BIP-85 seed phrase to save and encrypt.
            fingerprint_dir (Path): The directory corresponding to the fingerprint.
        """
        try:
            # Set self.fingerprint_dir
            self.fingerprint_dir = fingerprint_dir

            # Prompt for password
            password = prompt_for_password()
            # Derive key from password
            key = derive_key_from_password(password)
            # Re-initialize EncryptionManager with the new key and fingerprint_dir
            self.encryption_manager = EncryptionManager(key, fingerprint_dir)

            # Store the hashed password
            self.store_hashed_password(password)
            logging.info("User password hashed and stored successfully.")

            # Encrypt and save the parent seed
            self.encryption_manager.encrypt_parent_seed(seed)
            logging.info("Parent seed encrypted and saved successfully.")

            self.parent_seed = seed  # Ensure this is a string
            logger.debug(f"parent_seed set to: {self.parent_seed} (type: {type(self.parent_seed)})")

            self.initialize_bip85()
            self.initialize_managers()
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
        Initializes the EntryManager, PasswordGenerator, BackupManager, and NostrClient with the EncryptionManager
        and BIP-85 instance within the context of the selected fingerprint.
        """
        try:
            # Ensure self.encryption_manager is already initialized
            if not self.encryption_manager:
                raise ValueError("EncryptionManager is not initialized.")

            # Reinitialize the managers with the updated EncryptionManager and current fingerprint context
            self.entry_manager = EntryManager(
                encryption_manager=self.encryption_manager,
                fingerprint_dir=self.fingerprint_dir
            )
            
            self.password_generator = PasswordGenerator(
                encryption_manager=self.encryption_manager,
                parent_seed=self.parent_seed,
                bip85=self.bip85
            )
            
            self.backup_manager = BackupManager(fingerprint_dir=self.fingerprint_dir)

            # Initialize the NostrClient with the current fingerprint
            self.nostr_client = NostrClient(
                encryption_manager=self.encryption_manager,
                fingerprint=self.current_fingerprint  # Pass the current fingerprint
            )

            logger.debug("Managers re-initialized for the new fingerprint.")
        
        except Exception as e:
            logger.error(f"Failed to initialize managers: {e}")
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
            encrypted_data = self.entry_manager.get_encrypted_index()
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
            # Decrypt the data using EncryptionManager's decrypt_data method
            decrypted_data = self.encryption_manager.decrypt_data(encrypted_data)
            
            # Save the decrypted data to the index file
            index_file_path = self.fingerprint_dir / 'seedpass_passwords_db.json.enc'
            with open(index_file_path, 'wb') as f:
                f.write(decrypted_data)
                
            logging.info("Index file updated from Nostr successfully.")
            print(colored("Index file updated from Nostr successfully.", 'green'))
        except Exception as e:
            logging.error(f"Failed to decrypt and save data from Nostr: {e}")
            logging.error(traceback.format_exc())
            print(colored(f"Error: Failed to decrypt and save data from Nostr: {e}", 'red'))
            # Re-raise the exception to inform the calling function of the failure
            raise

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
                backup_path = self.fingerprint_dir / filename  # Save in fingerprint directory

                # Validate filename
                if not self.is_valid_filename(filename):
                    print(colored("Invalid filename. Operation aborted.", 'red'))
                    return

                # Encrypt and save the parent seed to the backup path
                self.encryption_manager.encrypt_and_save_file(self.parent_seed.encode('utf-8'), backup_path)
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
            hashed_password_file = self.fingerprint_dir / 'hashed_password.enc'
            if not hashed_password_file.exists():
                logging.error("Hashed password file not found.")
                print(colored("Error: Hashed password file not found.", 'red'))
                return False
            with open(hashed_password_file, 'rb') as f:
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
            hashed_password_file = self.fingerprint_dir / 'hashed_password.enc'
            hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            with open(hashed_password_file, 'wb') as f:
                f.write(hashed)
            os.chmod(hashed_password_file, 0o600)
            logging.info("User password hashed and stored successfully.")
        except AttributeError:
            # If bcrypt.hashpw is not available, try using bcrypt directly
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
            with open(hashed_password_file, 'wb') as f:
                f.write(hashed)
            os.chmod(hashed_password_file, 0o600)
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

    # Initialize NostrClient with the EncryptionManager from PasswordManager
    manager.nostr_client = NostrClient(encryption_manager=manager.encryption_manager)

    # Example operations
    # These would typically be triggered by user interactions, e.g., via a CLI menu
    # manager.handle_generate_password()
    # manager.handle_retrieve_password()
    # manager.handle_modify_entry()
    # manager.handle_verify_checksum()
    # manager.nostr_client.publish_and_subscribe("Sample password data")
    # manager.backup_database()
    # manager.restore_database()
