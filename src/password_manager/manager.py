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
import time
from termcolor import colored

from password_manager.encryption import EncryptionManager
from password_manager.entry_management import EntryManager
from password_manager.password_generation import PasswordGenerator
from password_manager.backup import BackupManager
from password_manager.vault import Vault
from password_manager.portable_backup import export_backup, import_backup
from utils.key_derivation import (
    derive_key_from_parent_seed,
    derive_key_from_password,
    derive_index_key,
    EncryptionMode,
)
from utils.checksum import calculate_checksum, verify_checksum
from utils.password_prompt import (
    prompt_for_password,
    prompt_existing_password,
    confirm_action,
)

from constants import (
    APP_DIR,
    PARENT_SEED_FILE,
    SCRIPT_CHECKSUM_FILE,
    MIN_PASSWORD_LENGTH,
    MAX_PASSWORD_LENGTH,
    DEFAULT_PASSWORD_LENGTH,
    INACTIVITY_TIMEOUT,
    DEFAULT_SEED_BACKUP_FILENAME,
    initialize_app,
)

import traceback
import asyncio
import gzip
import bcrypt
from pathlib import Path

from local_bip85.bip85 import BIP85, Bip85Error
from bip_utils import Bip39SeedGenerator, Bip39MnemonicGenerator, Bip39Languages
from datetime import datetime

from utils.fingerprint_manager import FingerprintManager

# Import NostrClient
from nostr.client import NostrClient, DEFAULT_RELAYS
from password_manager.config_manager import ConfigManager

# Instantiate the logger
logger = logging.getLogger(__name__)


class PasswordManager:
    """
    PasswordManager Class

    Manages the generation, encryption, and retrieval of deterministic passwords using a BIP-85 seed.
    It handles file encryption/decryption, password generation, entry management, backups, and checksum
    verification, ensuring the integrity and confidentiality of the stored password database.
    """

    def __init__(self) -> None:
        """Initialize the PasswordManager."""
        initialize_app()
        self.encryption_mode: EncryptionMode = EncryptionMode.SEED_ONLY
        self.encryption_manager: Optional[EncryptionManager] = None
        self.entry_manager: Optional[EntryManager] = None
        self.password_generator: Optional[PasswordGenerator] = None
        self.backup_manager: Optional[BackupManager] = None
        self.vault: Optional[Vault] = None
        self.fingerprint_manager: Optional[FingerprintManager] = None
        self.parent_seed: Optional[str] = None
        self.bip85: Optional[BIP85] = None
        self.nostr_client: Optional[NostrClient] = None
        self.config_manager: Optional[ConfigManager] = None

        # Track changes to trigger periodic Nostr sync
        self.is_dirty: bool = False
        self.last_update: float = time.time()
        self.last_activity: float = time.time()
        self.locked: bool = False
        self.inactivity_timeout: float = INACTIVITY_TIMEOUT

        # Initialize the fingerprint manager first
        self.initialize_fingerprint_manager()

        # Ensure a parent seed is set up before accessing the fingerprint directory
        self.setup_parent_seed()

        # Set the current fingerprint directory
        self.fingerprint_dir = self.fingerprint_manager.get_current_fingerprint_dir()

    def update_activity(self) -> None:
        """Record the current time as the last user activity."""
        self.last_activity = time.time()

    def lock_vault(self) -> None:
        """Clear sensitive information from memory."""
        self.parent_seed = None
        self.encryption_manager = None
        self.entry_manager = None
        self.password_generator = None
        self.backup_manager = None
        self.vault = None
        self.bip85 = None
        self.nostr_client = None
        self.config_manager = None
        self.locked = True

    def unlock_vault(self) -> None:
        """Prompt for password and reinitialize managers."""
        if not self.fingerprint_dir:
            raise ValueError("Fingerprint directory not set")
        self.setup_encryption_manager(self.fingerprint_dir)
        self.initialize_bip85()
        self.initialize_managers()
        self.locked = False
        self.update_activity()

    def initialize_fingerprint_manager(self):
        """
        Initializes the FingerprintManager.
        """
        try:
            self.fingerprint_manager = FingerprintManager(APP_DIR)
            logger.debug("FingerprintManager initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to initialize FingerprintManager: {e}", exc_info=True)
            print(
                colored(f"Error: Failed to initialize FingerprintManager: {e}", "red")
            )
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
            print(colored("\nAvailable Seed Profiles:", "cyan"))
            fingerprints = self.fingerprint_manager.list_fingerprints()
            for idx, fp in enumerate(fingerprints, start=1):
                print(colored(f"{idx}. {fp}", "cyan"))

            print(colored(f"{len(fingerprints)+1}. Add a new seed profile", "cyan"))

            choice = input("Select a seed profile by number: ").strip()
            if not choice.isdigit() or not (1 <= int(choice) <= len(fingerprints) + 1):
                print(colored("Invalid selection. Exiting.", "red"))
                sys.exit(1)

            choice = int(choice)
            if choice == len(fingerprints) + 1:
                # Add a new seed profile
                self.add_new_fingerprint()
            else:
                # Select existing seed profile
                selected_fingerprint = fingerprints[choice - 1]
                self.select_fingerprint(selected_fingerprint)

        except Exception as e:
            logger.error(f"Error during seed profile selection: {e}", exc_info=True)
            print(colored(f"Error: Failed to select seed profile: {e}", "red"))
            sys.exit(1)

    def add_new_fingerprint(self):
        """
        Adds a new seed profile by prompting for encryption mode and generating
        it from a seed phrase.
        """
        try:
            choice = input(
                "Do you want to (1) Enter an existing seed or (2) Generate a new seed? (1/2): "
            ).strip()
            if choice == "1":
                fingerprint = self.setup_existing_seed()
            elif choice == "2":
                fingerprint = self.generate_new_seed()
            else:
                print(colored("Invalid choice. Exiting.", "red"))
                sys.exit(1)

            # Set current_fingerprint in FingerprintManager only
            self.fingerprint_manager.current_fingerprint = fingerprint
            print(
                colored(
                    f"New seed profile '{fingerprint}' added and set as current.",
                    "green",
                )
            )

        except Exception as e:
            logger.error(f"Error adding new seed profile: {e}", exc_info=True)
            print(colored(f"Error: Failed to add new seed profile: {e}", "red"))
            sys.exit(1)

    def select_fingerprint(self, fingerprint: str) -> None:
        if self.fingerprint_manager.select_fingerprint(fingerprint):
            self.current_fingerprint = fingerprint  # Add this line
            self.fingerprint_dir = (
                self.fingerprint_manager.get_current_fingerprint_dir()
            )
            if not self.fingerprint_dir:
                print(
                    colored(
                        f"Error: Seed profile directory for {fingerprint} not found.",
                        "red",
                    )
                )
                sys.exit(1)
            # Setup the encryption manager and load parent seed
            self.setup_encryption_manager(self.fingerprint_dir)
            # Initialize BIP85 and other managers
            self.initialize_bip85()
            self.initialize_managers()
            self.sync_index_from_nostr_if_missing()
            print(
                colored(
                    f"Seed profile {fingerprint} selected and managers initialized.",
                    "green",
                )
            )
        else:
            print(colored(f"Error: Seed profile {fingerprint} not found.", "red"))
            sys.exit(1)

    def setup_encryption_manager(
        self,
        fingerprint_dir: Path,
        password: Optional[str] = None,
        *,
        exit_on_fail: bool = True,
    ) -> bool:
        """Set up encryption for the current fingerprint and load the seed."""

        try:
            if password is None:
                password = prompt_existing_password("Enter your master password: ")

            seed_key = derive_key_from_password(password)
            seed_mgr = EncryptionManager(seed_key, fingerprint_dir)
            try:
                self.parent_seed = seed_mgr.decrypt_parent_seed()
            except Exception:
                msg = "Invalid password for selected seed profile."
                print(colored(msg, "red"))
                if exit_on_fail:
                    sys.exit(1)
                return False

            key = derive_index_key(self.parent_seed)

            self.encryption_manager = EncryptionManager(key, fingerprint_dir)
            self.vault = Vault(self.encryption_manager, fingerprint_dir)

            self.config_manager = ConfigManager(
                vault=self.vault,
                fingerprint_dir=fingerprint_dir,
            )

            self.fingerprint_dir = fingerprint_dir
            if not self.verify_password(password):
                print(colored("Invalid password.", "red"))
                if exit_on_fail:
                    sys.exit(1)
                return False
            return True
        except Exception as e:
            logger.error(f"Failed to set up EncryptionManager: {e}", exc_info=True)
            print(colored(f"Error: Failed to set up encryption: {e}", "red"))
            if exit_on_fail:
                sys.exit(1)
            return False

    def load_parent_seed(
        self, fingerprint_dir: Path, password: Optional[str] = None
    ) -> None:
        """Load and decrypt the parent seed using the password-only key."""

        if self.parent_seed:
            return

        if password is None:
            password = prompt_existing_password("Enter your master password: ")

        try:
            seed_key = derive_key_from_password(password)
            seed_mgr = EncryptionManager(seed_key, fingerprint_dir)
            self.parent_seed = seed_mgr.decrypt_parent_seed()
            seed_bytes = Bip39SeedGenerator(self.parent_seed).Generate()
            self.bip85 = BIP85(seed_bytes)
        except Exception as e:
            logger.error(f"Failed to load parent seed: {e}", exc_info=True)
            print(colored(f"Error: Failed to load parent seed: {e}", "red"))
            sys.exit(1)

    def handle_switch_fingerprint(self) -> bool:
        """
        Handles switching to a different seed profile.

        Returns:
            bool: True if switch was successful, False otherwise.
        """
        try:
            print(colored("\nAvailable Seed Profiles:", "cyan"))
            fingerprints = self.fingerprint_manager.list_fingerprints()
            for idx, fp in enumerate(fingerprints, start=1):
                print(colored(f"{idx}. {fp}", "cyan"))

            choice = input("Select a seed profile by number to switch: ").strip()
            if not choice.isdigit() or not (1 <= int(choice) <= len(fingerprints)):
                print(colored("Invalid selection. Returning to main menu.", "red"))
                return False  # Return False to indicate failure

            selected_fingerprint = fingerprints[int(choice) - 1]
            self.fingerprint_manager.current_fingerprint = selected_fingerprint
            self.current_fingerprint = selected_fingerprint

            # Update fingerprint directory
            self.fingerprint_dir = (
                self.fingerprint_manager.get_current_fingerprint_dir()
            )
            if not self.fingerprint_dir:
                print(
                    colored(
                        f"Error: Seed profile directory for {selected_fingerprint} not found.",
                        "red",
                    )
                )
                return False  # Return False to indicate failure

            # Prompt for master password for the selected seed profile
            password = prompt_existing_password(
                "Enter the master password for the selected seed profile: "
            )

            # Set up the encryption manager with the new password and seed profile directory
            if not self.setup_encryption_manager(
                self.fingerprint_dir, password, exit_on_fail=False
            ):
                return False

            # Initialize BIP85 and other managers
            self.initialize_bip85()
            self.initialize_managers()
            self.sync_index_from_nostr_if_missing()
            print(colored(f"Switched to seed profile {selected_fingerprint}.", "green"))

            # Re-initialize NostrClient with the new fingerprint
            try:
                self.nostr_client = NostrClient(
                    encryption_manager=self.encryption_manager,
                    fingerprint=self.current_fingerprint,
                    parent_seed=getattr(self, "parent_seed", None),
                )
                logging.info(
                    f"NostrClient re-initialized with seed profile {self.current_fingerprint}."
                )
            except Exception as e:
                logging.error(f"Failed to re-initialize NostrClient: {e}")
                print(
                    colored(f"Error: Failed to re-initialize NostrClient: {e}", "red")
                )
                return False

            return True  # Return True to indicate success

        except Exception as e:
            logging.error(f"Error during seed profile switching: {e}", exc_info=True)
            print(colored(f"Error: Failed to switch seed profiles: {e}", "red"))
            return False  # Return False to indicate failure

    def handle_existing_seed(self) -> None:
        """
        Handles the scenario where an existing parent seed file is found.
        Prompts the user for the master password to decrypt the seed.
        """
        try:
            # Prompt for password
            password = getpass.getpass(prompt="Enter your login password: ").strip()

            # Derive encryption key from password
            key = derive_key_from_password(password)

            # Initialize FingerprintManager if not already initialized
            if not self.fingerprint_manager:
                self.initialize_fingerprint_manager()

            # Prompt the user to select an existing seed profile
            fingerprints = self.fingerprint_manager.list_fingerprints()
            if not fingerprints:
                print(
                    colored(
                        "No seed profiles available. Please add a seed profile first.",
                        "red",
                    )
                )
                sys.exit(1)

            print(colored("Available Seed Profiles:", "cyan"))
            for idx, fp in enumerate(fingerprints, start=1):
                print(colored(f"{idx}. {fp}", "cyan"))

            choice = input("Select a seed profile by number: ").strip()
            if not choice.isdigit() or not (1 <= int(choice) <= len(fingerprints)):
                print(colored("Invalid selection. Exiting.", "red"))
                sys.exit(1)

            selected_fingerprint = fingerprints[int(choice) - 1]
            self.current_fingerprint = selected_fingerprint
            fingerprint_dir = self.fingerprint_manager.get_fingerprint_directory(
                selected_fingerprint
            )
            if not fingerprint_dir:
                print(colored("Error: Seed profile directory not found.", "red"))
                sys.exit(1)

            # Initialize EncryptionManager with key and fingerprint_dir
            self.encryption_manager = EncryptionManager(key, fingerprint_dir)
            self.vault = Vault(self.encryption_manager, fingerprint_dir)
            self.parent_seed = self.encryption_manager.decrypt_parent_seed()

            # Log the type and content of parent_seed
            logger.debug(
                f"Decrypted parent_seed: {self.parent_seed} (type: {type(self.parent_seed)})"
            )

            # Validate the decrypted seed
            if not self.validate_bip85_seed(self.parent_seed):
                logging.error("Decrypted seed is invalid. Exiting.")
                print(colored("Error: Decrypted seed is invalid.", "red"))
                sys.exit(1)

            self.initialize_bip85()
            logging.debug("Parent seed decrypted and validated successfully.")
        except Exception as e:
            logging.error(f"Failed to decrypt parent seed: {e}", exc_info=True)
            print(colored(f"Error: Failed to decrypt parent seed: {e}", "red"))
            sys.exit(1)

    def handle_new_seed_setup(self) -> None:
        """
        Handles the setup process when no existing parent seed is found.
        Asks the user whether to enter an existing BIP-85 seed or generate a new one.
        """
        print(colored("No existing seed found. Let's set up a new one!", "yellow"))

        choice = input(
            "Do you want to (1) Enter an existing BIP-85 seed or (2) Generate a new BIP-85 seed? (1/2): "
        ).strip()

        if choice == "1":
            self.setup_existing_seed()
        elif choice == "2":
            self.generate_new_seed()
        else:
            print(colored("Invalid choice. Exiting.", "red"))
            sys.exit(1)

    def setup_existing_seed(self) -> Optional[str]:
        """
        Prompts the user to enter an existing BIP-85 seed and validates it.

        Returns:
            Optional[str]: The fingerprint if setup is successful, None otherwise.
        """
        try:
            parent_seed = getpass.getpass(
                prompt="Enter your 12-word BIP-85 seed: "
            ).strip()
            if self.validate_bip85_seed(parent_seed):
                # Add a fingerprint using the existing seed
                fingerprint = self.fingerprint_manager.add_fingerprint(parent_seed)
                if not fingerprint:
                    print(
                        colored(
                            "Error: Failed to generate seed profile for the provided seed.",
                            "red",
                        )
                    )
                    sys.exit(1)

                fingerprint_dir = self.fingerprint_manager.get_fingerprint_directory(
                    fingerprint
                )
                if not fingerprint_dir:
                    print(
                        colored(
                            "Error: Failed to retrieve seed profile directory.", "red"
                        )
                    )
                    sys.exit(1)

                # Set the current fingerprint in both PasswordManager and FingerprintManager
                self.current_fingerprint = fingerprint
                self.fingerprint_manager.current_fingerprint = fingerprint
                self.fingerprint_dir = fingerprint_dir
                logging.info(f"Current seed profile set to {fingerprint}")

                # Initialize EncryptionManager with key and fingerprint_dir
                password = prompt_for_password()
                index_key = derive_index_key(parent_seed)
                seed_key = derive_key_from_password(password)

                self.encryption_manager = EncryptionManager(index_key, fingerprint_dir)
                seed_mgr = EncryptionManager(seed_key, fingerprint_dir)
                self.vault = Vault(self.encryption_manager, fingerprint_dir)

                # Ensure config manager is set for the new fingerprint
                self.config_manager = ConfigManager(
                    vault=self.vault,
                    fingerprint_dir=fingerprint_dir,
                )

                # Encrypt and save the parent seed
                seed_mgr.encrypt_parent_seed(parent_seed)
                logging.info("Parent seed encrypted and saved successfully.")

                # Store the hashed password
                self.store_hashed_password(password)
                logging.info("User password hashed and stored successfully.")

                self.parent_seed = parent_seed  # Ensure this is a string
                logger.debug(
                    f"parent_seed set to: {self.parent_seed} (type: {type(self.parent_seed)})"
                )

                self.initialize_bip85()
                self.initialize_managers()
                self.sync_index_from_nostr_if_missing()
                return fingerprint  # Return the generated or added fingerprint
            else:
                logging.error("Invalid BIP-85 seed phrase. Exiting.")
                print(colored("Error: Invalid BIP-85 seed phrase.", "red"))
                sys.exit(1)
        except KeyboardInterrupt:
            logging.info("Operation cancelled by user.")
            print(colored("\nOperation cancelled by user.", "yellow"))
            sys.exit(0)

    def generate_new_seed(self) -> Optional[str]:
        """
        Generates a new BIP-85 seed, displays it to the user, and prompts for confirmation before saving.

        Returns:
            Optional[str]: The fingerprint if generation is successful, None otherwise.
        """
        new_seed = self.generate_bip85_seed()
        print(colored("Your new BIP-85 seed phrase is:", "green"))
        print(colored(new_seed, "yellow"))
        print(colored("Please write this down and keep it in a safe place!", "red"))

        if confirm_action("Do you want to use this generated seed? (Y/N): "):
            # Add a new fingerprint using the generated seed
            fingerprint = self.fingerprint_manager.add_fingerprint(new_seed)
            if not fingerprint:
                print(
                    colored(
                        "Error: Failed to generate seed profile for the new seed.",
                        "red",
                    )
                )
                sys.exit(1)

            fingerprint_dir = self.fingerprint_manager.get_fingerprint_directory(
                fingerprint
            )
            if not fingerprint_dir:
                print(
                    colored("Error: Failed to retrieve seed profile directory.", "red")
                )
                sys.exit(1)

            # Set the current fingerprint in both PasswordManager and FingerprintManager
            self.current_fingerprint = fingerprint
            self.fingerprint_manager.current_fingerprint = fingerprint
            logging.info(f"Current seed profile set to {fingerprint}")

            # Now, save and encrypt the seed with the fingerprint_dir
            self.save_and_encrypt_seed(new_seed, fingerprint_dir)

            return fingerprint  # Return the generated fingerprint
        else:
            print(colored("Seed generation cancelled. Exiting.", "yellow"))
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
            mnemonic = bip85.derive_mnemonic(index=0, words_num=12)
            return mnemonic
        except Bip85Error as e:
            logging.error(f"Failed to generate BIP-85 seed: {e}", exc_info=True)
            print(colored(f"Error: Failed to generate BIP-85 seed: {e}", "red"))
            sys.exit(1)
        except Exception as e:
            logging.error(f"Failed to generate BIP-85 seed: {e}", exc_info=True)
            print(colored(f"Error: Failed to generate BIP-85 seed: {e}", "red"))
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

            index_key = derive_index_key(seed)
            seed_key = derive_key_from_password(password)

            self.encryption_manager = EncryptionManager(index_key, fingerprint_dir)
            seed_mgr = EncryptionManager(seed_key, fingerprint_dir)

            self.vault = Vault(self.encryption_manager, fingerprint_dir)

            # Ensure the config manager points to the new fingerprint before
            # storing the hashed password
            self.config_manager = ConfigManager(
                vault=self.vault,
                fingerprint_dir=fingerprint_dir,
            )

            self.store_hashed_password(password)
            logging.info("User password hashed and stored successfully.")

            seed_mgr.encrypt_parent_seed(seed)
            logging.info("Parent seed encrypted and saved successfully.")

            self.parent_seed = seed  # Ensure this is a string
            logger.debug(
                f"parent_seed set to: {self.parent_seed} (type: {type(self.parent_seed)})"
            )

            self.initialize_bip85()
            self.initialize_managers()
            self.sync_index_from_nostr_if_missing()
        except Exception as e:
            logging.error(f"Failed to encrypt and save parent seed: {e}", exc_info=True)
            print(colored(f"Error: Failed to encrypt and save parent seed: {e}", "red"))
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
            logging.error(f"Failed to initialize BIP-85: {e}", exc_info=True)
            print(colored(f"Error: Failed to initialize BIP-85: {e}", "red"))
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
                vault=self.vault,
                fingerprint_dir=self.fingerprint_dir,
            )

            self.password_generator = PasswordGenerator(
                encryption_manager=self.encryption_manager,
                parent_seed=self.parent_seed,
                bip85=self.bip85,
            )

            self.backup_manager = BackupManager(fingerprint_dir=self.fingerprint_dir)

            # Load relay configuration and initialize NostrClient
            self.config_manager = ConfigManager(
                vault=self.vault,
                fingerprint_dir=self.fingerprint_dir,
            )
            config = self.config_manager.load_config()
            relay_list = config.get("relays", list(DEFAULT_RELAYS))
            self.inactivity_timeout = config.get(
                "inactivity_timeout", INACTIVITY_TIMEOUT
            )

            self.nostr_client = NostrClient(
                encryption_manager=self.encryption_manager,
                fingerprint=self.current_fingerprint,
                relays=relay_list,
                parent_seed=getattr(self, "parent_seed", None),
            )

            logger.debug("Managers re-initialized for the new fingerprint.")

        except Exception as e:
            logger.error(f"Failed to initialize managers: {e}", exc_info=True)
            print(colored(f"Error: Failed to initialize managers: {e}", "red"))
            sys.exit(1)

    def sync_index_from_nostr_if_missing(self) -> None:
        """Retrieve the password database from Nostr if it doesn't exist locally."""
        index_file = self.fingerprint_dir / "seedpass_entries_db.json.enc"
        if index_file.exists():
            return
        try:
            result = asyncio.run(self.nostr_client.fetch_latest_snapshot())
            if result:
                manifest, chunks = result
                encrypted = gzip.decompress(b"".join(chunks))
                if manifest.delta_since:
                    try:
                        version = int(manifest.delta_since)
                        deltas = asyncio.run(
                            self.nostr_client.fetch_deltas_since(version)
                        )
                        if deltas:
                            encrypted = deltas[-1]
                    except ValueError:
                        pass
                self.vault.decrypt_and_save_index_from_nostr(encrypted)
                logger.info("Initialized local database from Nostr.")
        except Exception as e:
            logger.warning(f"Unable to sync index from Nostr: {e}")

    def handle_add_password(self) -> None:
        try:
            website_name = input("Enter the website name: ").strip()
            if not website_name:
                print(colored("Error: Website name cannot be empty.", "red"))
                return

            username = input("Enter the username (optional): ").strip()
            url = input("Enter the URL (optional): ").strip()
            notes = input("Enter notes (optional): ").strip()

            length_input = input(
                f"Enter desired password length (default {DEFAULT_PASSWORD_LENGTH}): "
            ).strip()
            length = DEFAULT_PASSWORD_LENGTH
            if length_input:
                if not length_input.isdigit():
                    print(colored("Error: Password length must be a number.", "red"))
                    return
                length = int(length_input)
                if not (MIN_PASSWORD_LENGTH <= length <= MAX_PASSWORD_LENGTH):
                    print(
                        colored(
                            f"Error: Password length must be between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH}.",
                            "red",
                        )
                    )
                    return

            # Add the entry to the index and get the assigned index
            index = self.entry_manager.add_entry(
                website_name,
                length,
                username,
                url,
                blacklisted=False,
                notes=notes,
            )

            # Mark database as dirty for background sync
            self.is_dirty = True
            self.last_update = time.time()

            # Generate the password using the assigned index
            password = self.password_generator.generate_password(length, index)

            # Provide user feedback
            print(
                colored(
                    f"\n[+] Password generated and indexed with ID {index}.\n",
                    "green",
                )
            )
            print(colored(f"Password for {website_name}: {password}\n", "yellow"))

            # Automatically push the updated encrypted index to Nostr so the
            # latest changes are backed up remotely.
            try:
                self.sync_vault()
                logging.info("Encrypted index posted to Nostr after entry addition.")
            except Exception as nostr_error:
                logging.error(
                    f"Failed to post updated index to Nostr: {nostr_error}",
                    exc_info=True,
                )

        except Exception as e:
            logging.error(f"Error during password generation: {e}", exc_info=True)
            print(colored(f"Error: Failed to generate password: {e}", "red"))

    def handle_add_totp(self) -> None:
        """Prompt for details and add a new TOTP entry."""
        try:
            label = input("Enter the account label: ").strip()
            if not label:
                print(colored("Error: Label cannot be empty.", "red"))
                return

            totp_index = self.entry_manager.get_next_totp_index()

            period_input = input("TOTP period in seconds (default 30): ").strip()
            period = 30
            if period_input:
                if not period_input.isdigit():
                    print(colored("Error: Period must be a number.", "red"))
                    return
                period = int(period_input)

            digits_input = input("Number of digits (default 6): ").strip()
            digits = 6
            if digits_input:
                if not digits_input.isdigit():
                    print(colored("Error: Digits must be a number.", "red"))
                    return
                digits = int(digits_input)

            entry_id = self.entry_manager.get_next_index()
            uri = self.entry_manager.add_totp(
                label,
                self.parent_seed,
                index=totp_index,
                period=period,
                digits=digits,
            )

            self.is_dirty = True
            self.last_update = time.time()

            secret = TotpManager.derive_secret(self.parent_seed, totp_index)

            print(colored(f"\n[+] TOTP entry added with ID {entry_id}.\n", "green"))
            print(colored("Add this URI to your authenticator app:", "cyan"))
            print(colored(uri, "yellow"))
            print(colored(f"Secret: {secret}\n", "cyan"))

            try:
                self.sync_vault()
                logging.info("Encrypted index posted to Nostr after TOTP add.")
            except Exception as nostr_error:
                logging.error(
                    f"Failed to post updated index to Nostr: {nostr_error}",
                    exc_info=True,
                )

        except Exception as e:
            logging.error(f"Error during TOTP setup: {e}", exc_info=True)
            print(colored(f"Error: Failed to add TOTP: {e}", "red"))

    def handle_retrieve_entry(self) -> None:
        """
        Handles retrieving a password from the index by prompting the user for the index number
        and displaying the corresponding password and associated details.
        """
        try:
            index_input = input(
                "Enter the index number of the password to retrieve: "
            ).strip()
            if not index_input.isdigit():
                print(colored("Error: Index must be a number.", "red"))
                return
            index = int(index_input)

            # Retrieve entry details
            entry = self.entry_manager.retrieve_entry(index)
            if not entry:
                return

            # Display entry details
            website_name = entry.get("website")
            length = entry.get("length")
            username = entry.get("username")
            url = entry.get("url")
            blacklisted = entry.get("blacklisted")
            notes = entry.get("notes", "")
            notes = entry.get("notes", "")
            notes = entry.get("notes", "")
            notes = entry.get("notes", "")

            print(
                colored(
                    f"Retrieving password for '{website_name}' with length {length}.",
                    "cyan",
                )
            )
            if username:
                print(colored(f"Username: {username}", "cyan"))
            if url:
                print(colored(f"URL: {url}", "cyan"))
            if blacklisted:
                print(
                    colored(
                        f"Warning: This password is blacklisted and should not be used.",
                        "red",
                    )
                )

            # Generate the password
            password = self.password_generator.generate_password(length, index)

            # Display the password and associated details
            if password:
                print(
                    colored(f"\n[+] Retrieved Password for {website_name}:\n", "green")
                )
                print(colored(f"Password: {password}", "yellow"))
                print(colored(f"Associated Username: {username or 'N/A'}", "cyan"))
                print(colored(f"Associated URL: {url or 'N/A'}", "cyan"))
                print(
                    colored(
                        f"Blacklist Status: {'Blacklisted' if blacklisted else 'Not Blacklisted'}",
                        "cyan",
                    )
                )
            else:
                print(colored("Error: Failed to retrieve the password.", "red"))
        except Exception as e:
            logging.error(f"Error during password retrieval: {e}", exc_info=True)
            print(colored(f"Error: Failed to retrieve password: {e}", "red"))

    def handle_modify_entry(self) -> None:
        """
        Handles modifying an existing password entry by prompting the user for the index number
        and new details to update.
        """
        try:
            index_input = input(
                "Enter the index number of the entry to modify: "
            ).strip()
            if not index_input.isdigit():
                print(colored("Error: Index must be a number.", "red"))
                return
            index = int(index_input)

            # Retrieve existing entry
            entry = self.entry_manager.retrieve_entry(index)
            if not entry:
                return

            website_name = entry.get("website")
            length = entry.get("length")
            username = entry.get("username")
            url = entry.get("url")
            blacklisted = entry.get("blacklisted")
            notes = entry.get("notes", "")

            # Display current values
            print(
                colored(
                    f"Modifying entry for '{website_name}' (Index: {index}):", "cyan"
                )
            )
            print(colored(f"Current Username: {username or 'N/A'}", "cyan"))
            print(colored(f"Current URL: {url or 'N/A'}", "cyan"))
            print(
                colored(
                    f"Current Blacklist Status: {'Blacklisted' if blacklisted else 'Not Blacklisted'}",
                    "cyan",
                )
            )

            # Prompt for new values (optional)
            new_username = (
                input(
                    f'Enter new username (leave blank to keep "{username or "N/A"}"): '
                ).strip()
                or username
            )
            new_url = (
                input(f'Enter new URL (leave blank to keep "{url or "N/A"}"): ').strip()
                or url
            )
            blacklist_input = (
                input(
                    f'Is this password blacklisted? (Y/N, current: {"Y" if blacklisted else "N"}): '
                )
                .strip()
                .lower()
            )
            if blacklist_input == "":
                new_blacklisted = blacklisted
            elif blacklist_input == "y":
                new_blacklisted = True
            elif blacklist_input == "n":
                new_blacklisted = False
            else:
                print(
                    colored(
                        "Invalid input for blacklist status. Keeping the current status.",
                        "yellow",
                    )
                )
                new_blacklisted = blacklisted

            new_notes = (
                input(
                    f'Enter new notes (leave blank to keep "{notes or "N/A"}"): '
                ).strip()
                or notes
            )

            # Update the entry
            self.entry_manager.modify_entry(
                index,
                new_username,
                new_url,
                new_blacklisted,
                new_notes,
            )

            # Mark database as dirty for background sync
            self.is_dirty = True
            self.last_update = time.time()

            print(colored(f"Entry updated successfully for index {index}.", "green"))

            # Push the updated index to Nostr so changes are backed up.
            try:
                self.sync_vault()
                logging.info(
                    "Encrypted index posted to Nostr after entry modification."
                )
            except Exception as nostr_error:
                logging.error(
                    f"Failed to post updated index to Nostr: {nostr_error}",
                    exc_info=True,
                )

        except Exception as e:
            logging.error(f"Error during modifying entry: {e}", exc_info=True)
            print(colored(f"Error: Failed to modify entry: {e}", "red"))

    def delete_entry(self) -> None:
        """Deletes an entry from the password index."""
        try:
            index_input = input(
                "Enter the index number of the entry to delete: "
            ).strip()
            if not index_input.isdigit():
                print(colored("Error: Index must be a number.", "red"))
                return
            index_to_delete = int(index_input)

            if not confirm_action(
                f"Are you sure you want to delete entry {index_to_delete}? (Y/N): "
            ):
                print(colored("Deletion cancelled.", "yellow"))
                return

            self.entry_manager.delete_entry(index_to_delete)

            # Mark database as dirty for background sync
            self.is_dirty = True
            self.last_update = time.time()

            # Push updated index to Nostr after deletion
            try:
                self.sync_vault()
                logging.info("Encrypted index posted to Nostr after entry deletion.")
            except Exception as nostr_error:
                logging.error(
                    f"Failed to post updated index to Nostr: {nostr_error}",
                    exc_info=True,
                )

        except Exception as e:
            logging.error(f"Error during entry deletion: {e}", exc_info=True)
            print(colored(f"Error: Failed to delete entry: {e}", "red"))

    def handle_verify_checksum(self) -> None:
        """
        Handles verifying the script's checksum against the stored checksum to ensure integrity.
        """
        try:
            current_checksum = calculate_checksum(__file__)
            try:
                verified = verify_checksum(current_checksum, SCRIPT_CHECKSUM_FILE)
            except FileNotFoundError:
                print(
                    colored(
                        "Checksum file missing. Run scripts/update_checksum.py to generate it.",
                        "yellow",
                    )
                )
                logging.warning("Checksum file missing during verification.")
                return

            if verified:
                print(colored("Checksum verification passed.", "green"))
                logging.info("Checksum verification passed.")
            else:
                print(
                    colored(
                        "Checksum verification failed. The script may have been modified.",
                        "red",
                    )
                )
                logging.error("Checksum verification failed.")
        except Exception as e:
            logging.error(f"Error during checksum verification: {e}", exc_info=True)
            print(colored(f"Error: Failed to verify checksum: {e}", "red"))

    def get_encrypted_data(self) -> Optional[bytes]:
        """
        Retrieves the encrypted password index data.

        :return: The encrypted data as bytes, or None if retrieval fails.
        """
        try:
            encrypted_data = self.vault.get_encrypted_index()
            if encrypted_data:
                logging.debug("Encrypted index data retrieved successfully.")
                return encrypted_data
            else:
                logging.error("Failed to retrieve encrypted index data.")
                print(colored("Error: Failed to retrieve encrypted index data.", "red"))
                return None
        except Exception as e:
            logging.error(f"Error retrieving encrypted data: {e}", exc_info=True)
            print(colored(f"Error: Failed to retrieve encrypted data: {e}", "red"))
            return None

    def decrypt_and_save_index_from_nostr(self, encrypted_data: bytes) -> None:
        """
        Decrypts the encrypted data retrieved from Nostr and updates the local index.

        :param encrypted_data: The encrypted data retrieved from Nostr.
        """
        try:
            self.vault.decrypt_and_save_index_from_nostr(encrypted_data)
            logging.info("Index file updated from Nostr successfully.")
            print(colored("Index file updated from Nostr successfully.", "green"))
        except Exception as e:
            logging.error(
                f"Failed to decrypt and save data from Nostr: {e}", exc_info=True
            )
            print(
                colored(
                    f"Error: Failed to decrypt and save data from Nostr: {e}", "red"
                )
            )
            # Re-raise the exception to inform the calling function of the failure
            raise

    def sync_vault(self, alt_summary: str | None = None) -> str | None:
        """Publish the current vault contents to Nostr."""
        try:
            encrypted = self.get_encrypted_data()
            if not encrypted:
                return None
            pub_snap = getattr(self.nostr_client, "publish_snapshot", None)
            if callable(pub_snap):
                if asyncio.iscoroutinefunction(pub_snap):
                    _, event_id = asyncio.run(pub_snap(encrypted))
                else:
                    _, event_id = pub_snap(encrypted)
            else:
                # Fallback for tests using simplified stubs
                event_id = self.nostr_client.publish_json_to_nostr(encrypted)
            self.is_dirty = False
            return event_id
        except Exception as e:
            logging.error(f"Failed to sync vault: {e}", exc_info=True)
            return None

    def backup_database(self) -> None:
        """
        Creates a backup of the encrypted JSON index file.
        """
        try:
            self.backup_manager.create_backup()
            print(colored("Backup created successfully.", "green"))
        except Exception as e:
            logging.error(f"Failed to create backup: {e}", exc_info=True)
            print(colored(f"Error: Failed to create backup: {e}", "red"))

    def restore_database(self) -> None:
        """
        Restores the encrypted JSON index file from the latest backup.
        """
        try:
            self.backup_manager.restore_latest_backup()
            print(
                colored(
                    "Database restored from the latest backup successfully.", "green"
                )
            )
        except Exception as e:
            logging.error(f"Failed to restore backup: {e}", exc_info=True)
            print(colored(f"Error: Failed to restore backup: {e}", "red"))

    def handle_export_database(
        self,
        dest: Path | None = None,
    ) -> Path | None:
        """Export the current database to an encrypted portable file."""
        try:
            path = export_backup(
                self.vault,
                self.backup_manager,
                dest,
                parent_seed=self.parent_seed,
            )
            print(colored(f"Database exported to '{path}'.", "green"))
            return path
        except Exception as e:
            logging.error(f"Failed to export database: {e}", exc_info=True)
            print(colored(f"Error: Failed to export database: {e}", "red"))
            return None

    def handle_import_database(self, src: Path) -> None:
        """Import a portable database file, replacing the current index."""
        try:
            import_backup(
                self.vault,
                self.backup_manager,
                src,
                parent_seed=self.parent_seed,
            )
            print(colored("Database imported successfully.", "green"))
        except Exception as e:
            logging.error(f"Failed to import database: {e}", exc_info=True)
            print(colored(f"Error: Failed to import database: {e}", "red"))

    def handle_backup_reveal_parent_seed(self) -> None:
        """
        Handles the backup and reveal of the parent seed.
        """
        try:
            print(colored("\n=== Backup Parent Seed ===", "yellow"))
            print(
                colored(
                    "Warning: Revealing your parent seed is a highly sensitive operation.",
                    "red",
                )
            )
            print(
                colored(
                    "Ensure you're in a secure, private environment and no one is watching your screen.",
                    "red",
                )
            )

            # Verify user's identity with secure password verification
            password = prompt_existing_password(
                "Enter your master password to continue: "
            )
            if not self.verify_password(password):
                print(colored("Incorrect password. Operation aborted.", "red"))
                return

            # Double confirmation
            if not confirm_action(
                "Are you absolutely sure you want to reveal your parent seed? (Y/N): "
            ):
                print(colored("Operation cancelled by user.", "yellow"))
                return

            # Reveal the parent seed
            print(colored("\n=== Your BIP-85 Parent Seed ===", "green"))
            print(colored(self.parent_seed, "yellow"))
            print(
                colored(
                    "\nPlease write this down and store it securely. Do not share it with anyone.",
                    "red",
                )
            )

            # Option to save to file with default filename
            if confirm_action(
                "Do you want to save this to an encrypted backup file? (Y/N): "
            ):
                filename = input(
                    f"Enter filename to save (default: {DEFAULT_SEED_BACKUP_FILENAME}): "
                ).strip()
                filename = filename if filename else DEFAULT_SEED_BACKUP_FILENAME
                backup_path = (
                    self.fingerprint_dir / filename
                )  # Save in fingerprint directory

                # Validate filename
                if not self.is_valid_filename(filename):
                    print(colored("Invalid filename. Operation aborted.", "red"))
                    return

                # Encrypt and save the parent seed to the backup path
                self.encryption_manager.encrypt_and_save_file(
                    self.parent_seed.encode("utf-8"), backup_path
                )
                print(
                    colored(
                        f"Encrypted seed backup saved to '{backup_path}'. Ensure this file is stored securely.",
                        "green",
                    )
                )

        except Exception as e:
            logging.error(f"Error during parent seed backup/reveal: {e}", exc_info=True)
            print(colored(f"Error: Failed to backup/reveal parent seed: {e}", "red"))

    def verify_password(self, password: str) -> bool:
        """
        Verifies the provided password against the stored hashed password.

        Parameters:
            password (str): The password to verify.

        Returns:
            bool: True if the password is correct, False otherwise.
        """
        try:
            config = self.config_manager.load_config(require_pin=False)
            stored_hash = config.get("password_hash", "").encode()
            if not stored_hash:
                # Fallback to legacy file if hash not present in config
                legacy_file = self.fingerprint_dir / "hashed_password.enc"
                if legacy_file.exists():
                    with open(legacy_file, "rb") as f:
                        stored_hash = f.read()
                    self.config_manager.set_password_hash(stored_hash.decode())
                else:
                    logging.error("Hashed password not found.")
                    print(colored("Error: Hashed password not found.", "red"))
                    return False

            is_correct = bcrypt.checkpw(password.encode("utf-8"), stored_hash)
            if is_correct:
                logging.debug("Password verification successful.")
            else:
                logging.warning("Password verification failed.")
            return is_correct
        except Exception as e:
            logging.error(f"Error verifying password: {e}", exc_info=True)
            print(colored(f"Error: Failed to verify password: {e}", "red"))
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
        invalid_chars = ["/", "\\", ".."]
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
            hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode()
            if self.config_manager:
                self.config_manager.set_password_hash(hashed)
            else:
                # Fallback to legacy file method if config_manager unavailable
                hashed_password_file = self.fingerprint_dir / "hashed_password.enc"
                with open(hashed_password_file, "wb") as f:
                    f.write(hashed.encode())
                os.chmod(hashed_password_file, 0o600)
            logging.info("User password hashed and stored successfully.")
        except AttributeError:
            # If bcrypt.hashpw is not available, try using bcrypt directly
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(password.encode("utf-8"), salt).decode()
            if self.config_manager:
                self.config_manager.set_password_hash(hashed)
            else:
                hashed_password_file = self.fingerprint_dir / "hashed_password.enc"
                with open(hashed_password_file, "wb") as f:
                    f.write(hashed.encode())
                os.chmod(hashed_password_file, 0o600)
            logging.info(
                "User password hashed and stored successfully (using alternative method)."
            )
        except Exception as e:
            logging.error(f"Failed to store hashed password: {e}", exc_info=True)
            print(colored(f"Error: Failed to store hashed password: {e}", "red"))
            raise

    def change_password(self) -> None:
        """Change the master password used for encryption."""
        try:
            current = prompt_existing_password("Enter your current master password: ")
            if not self.verify_password(current):
                print(colored("Incorrect password.", "red"))
                return

            new_password = prompt_for_password()

            # Load data with existing encryption manager
            index_data = self.vault.load_index()
            config_data = self.config_manager.load_config(require_pin=False)

            # Create a new encryption manager with the new password
            new_key = derive_index_key(self.parent_seed)

            seed_key = derive_key_from_password(new_password)
            seed_mgr = EncryptionManager(seed_key, self.fingerprint_dir)

            new_enc_mgr = EncryptionManager(new_key, self.fingerprint_dir)

            seed_mgr.encrypt_parent_seed(self.parent_seed)
            self.vault.set_encryption_manager(new_enc_mgr)
            self.vault.save_index(index_data)
            self.config_manager.vault = self.vault
            self.config_manager.save_config(config_data)

            # Update hashed password and replace managers
            self.encryption_manager = new_enc_mgr
            self.password_generator.encryption_manager = new_enc_mgr
            self.store_hashed_password(new_password)

            relay_list = config_data.get("relays", list(DEFAULT_RELAYS))
            self.nostr_client = NostrClient(
                encryption_manager=self.encryption_manager,
                fingerprint=self.current_fingerprint,
                relays=relay_list,
                parent_seed=getattr(self, "parent_seed", None),
            )

            print(colored("Master password changed successfully.", "green"))

            # Push a fresh backup to Nostr so the newly encrypted index is
            # stored remotely. Include a tag to mark the password change.
            try:
                summary = f"password-change-{int(time.time())}"
                self.sync_vault(alt_summary=summary)
            except Exception as nostr_error:
                logging.error(
                    f"Failed to post updated index to Nostr after password change: {nostr_error}"
                )
        except Exception as e:
            logging.error(f"Failed to change password: {e}", exc_info=True)
            print(colored(f"Error: Failed to change password: {e}", "red"))
