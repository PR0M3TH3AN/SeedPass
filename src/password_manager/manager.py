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
import hashlib
from typing import Optional
import shutil
import time
import builtins
import threading
import queue
from dataclasses import dataclass
from termcolor import colored
from utils.color_scheme import color_text
from utils.input_utils import timed_input

from password_manager.encryption import EncryptionManager
from password_manager.entry_management import EntryManager
from password_manager.password_generation import PasswordGenerator
from password_manager.backup import BackupManager
from password_manager.vault import Vault
from password_manager.portable_backup import export_backup, import_backup
from password_manager.totp import TotpManager
from password_manager.entry_types import EntryType
from utils.key_derivation import (
    derive_key_from_parent_seed,
    derive_key_from_password,
    derive_key_from_password_argon2,
    derive_index_key,
    EncryptionMode,
)
from utils.checksum import (
    calculate_checksum,
    verify_checksum,
    json_checksum,
    initialize_checksum,
    update_checksum_file,
)
from utils.password_prompt import (
    prompt_for_password,
    prompt_existing_password,
    prompt_new_password,
    confirm_action,
)
from utils.memory_protection import InMemorySecret
from utils.clipboard import copy_to_clipboard
from utils.terminal_utils import (
    clear_screen,
    pause,
    clear_and_print_fingerprint,
    clear_and_print_profile_chain,
)
from utils.fingerprint import generate_fingerprint
from constants import MIN_HEALTHY_RELAYS
from password_manager.migrations import LATEST_VERSION

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


@dataclass
class Notification:
    """Simple message container for UI notifications."""

    message: str
    level: str = "INFO"


class PasswordManager:
    """
    PasswordManager Class

    Manages the generation, encryption, and retrieval of deterministic passwords using a BIP-85 seed.
    It handles file encryption/decryption, password generation, entry management, backups, and checksum
    verification, ensuring the integrity and confidentiality of the stored password database.
    """

    def __init__(self, fingerprint: Optional[str] = None) -> None:
        """Initialize the PasswordManager.

        Parameters
        ----------
        fingerprint:
            Optional seed profile fingerprint to select without prompting.
        """
        initialize_app()
        self.ensure_script_checksum()
        self.encryption_mode: EncryptionMode = EncryptionMode.SEED_ONLY
        self.encryption_manager: Optional[EncryptionManager] = None
        self.entry_manager: Optional[EntryManager] = None
        self.password_generator: Optional[PasswordGenerator] = None
        self.backup_manager: Optional[BackupManager] = None
        self.vault: Optional[Vault] = None
        self.fingerprint_manager: Optional[FingerprintManager] = None
        self._parent_seed_secret: Optional[InMemorySecret] = None
        self.bip85: Optional[BIP85] = None
        self.nostr_client: Optional[NostrClient] = None
        self.config_manager: Optional[ConfigManager] = None
        self.notifications: queue.Queue[Notification] = queue.Queue()

        # Track changes to trigger periodic Nostr sync
        self.is_dirty: bool = False
        self.last_update: float = time.time()
        self.last_activity: float = time.time()
        self.locked: bool = False
        self.inactivity_timeout: float = INACTIVITY_TIMEOUT
        self.secret_mode_enabled: bool = False
        self.clipboard_clear_delay: int = 45
        self.offline_mode: bool = False
        self.profile_stack: list[tuple[str, Path, str]] = []
        self.last_unlock_duration: float | None = None
        self.verbose_timing: bool = False

        # Initialize the fingerprint manager first
        self.initialize_fingerprint_manager()

        if fingerprint:
            # Load the specified profile without prompting
            self.select_fingerprint(fingerprint)
        else:
            # Ensure a parent seed is set up before accessing the fingerprint directory
            self.setup_parent_seed()
            # Set the current fingerprint directory after selection
            self.fingerprint_dir = (
                self.fingerprint_manager.get_current_fingerprint_dir()
            )

    def ensure_script_checksum(self) -> None:
        """Initialize or verify the checksum of the manager script."""
        script_path = Path(__file__).resolve()
        if not SCRIPT_CHECKSUM_FILE.exists():
            initialize_checksum(str(script_path), SCRIPT_CHECKSUM_FILE)
            return
        checksum = calculate_checksum(str(script_path))
        if checksum and not verify_checksum(checksum, SCRIPT_CHECKSUM_FILE):
            logging.warning("Script checksum mismatch detected on startup")
            print(
                colored(
                    "Warning: script checksum mismatch. "
                    "Run 'Generate Script Checksum' in Settings if you've updated the app.",
                    "yellow",
                )
            )

    @property
    def parent_seed(self) -> Optional[str]:
        """Return the decrypted parent seed if set."""
        if self._parent_seed_secret is None:
            return None
        return self._parent_seed_secret.get_str()

    @parent_seed.setter
    def parent_seed(self, value: Optional[str]) -> None:
        if value is None:
            if self._parent_seed_secret:
                self._parent_seed_secret.wipe()
            self._parent_seed_secret = None
        else:
            self._parent_seed_secret = InMemorySecret(value.encode("utf-8"))

    @property
    def header_fingerprint(self) -> str | None:
        """Return the fingerprint chain for header display."""
        if not getattr(self, "current_fingerprint", None):
            return None
        if not self.profile_stack:
            return self.current_fingerprint
        chain = [fp for fp, _path, _seed in self.profile_stack] + [
            self.current_fingerprint
        ]
        header = chain[0]
        for fp in chain[1:]:
            header += f" > Managed Account > {fp}"
        return header

    @property
    def header_fingerprint_args(self) -> tuple[str | None, str | None, str | None]:
        """Return fingerprint parameters for header display."""
        if not getattr(self, "current_fingerprint", None):
            return (None, None, None)
        if not self.profile_stack:
            return (self.current_fingerprint, None, None)
        parent_fp = self.profile_stack[-1][0]
        return (None, parent_fp, self.current_fingerprint)

    def update_activity(self) -> None:
        """Record the current time as the last user activity."""
        self.last_activity = time.time()

    def notify(self, message: str, level: str = "INFO") -> None:
        """Enqueue a notification for later retrieval."""
        self.notifications.put(Notification(message, level))

    def lock_vault(self) -> None:
        """Clear sensitive information from memory."""
        if self.entry_manager is not None:
            self.entry_manager.clear_cache()
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
        start = time.perf_counter()
        if not self.fingerprint_dir:
            raise ValueError("Fingerprint directory not set")
        self.setup_encryption_manager(self.fingerprint_dir)
        self.initialize_bip85()
        self.initialize_managers()
        self.locked = False
        self.update_activity()
        self.last_unlock_duration = time.perf_counter() - start
        print(
            colored(
                f"Vault unlocked in {self.last_unlock_duration:.2f} seconds",
                "yellow",
            )
        )
        if getattr(self, "verbose_timing", False):
            logger.info("Vault unlocked in %.2f seconds", self.last_unlock_duration)

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
            fingerprints = self.fingerprint_manager.list_fingerprints()
            current = self.fingerprint_manager.current_fingerprint

            # Auto-select when only one fingerprint exists
            if len(fingerprints) == 1:
                self.select_fingerprint(fingerprints[0])
                return

            print(colored("\nAvailable Seed Profiles:", "cyan"))
            for idx, fp in enumerate(fingerprints, start=1):
                marker = " *" if fp == current else ""
                print(colored(f"{idx}. {fp}{marker}", "cyan"))

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

        attempts = 0
        max_attempts = 5
        while attempts < max_attempts:
            try:
                if password is None:
                    password = prompt_existing_password("Enter your master password: ")

                mode = (
                    self.config_manager.get_kdf_mode()
                    if getattr(self, "config_manager", None)
                    else "pbkdf2"
                )
                iterations = (
                    self.config_manager.get_kdf_iterations()
                    if getattr(self, "config_manager", None)
                    else 50_000
                )
                print("Deriving key...")
                if mode == "argon2":
                    seed_key = derive_key_from_password_argon2(password)
                else:
                    seed_key = derive_key_from_password(password, iterations=iterations)
                seed_mgr = EncryptionManager(seed_key, fingerprint_dir)
                print("Decrypting seed...")
                try:
                    self.parent_seed = seed_mgr.decrypt_parent_seed()
                except Exception:
                    msg = (
                        "Invalid password for selected seed profile. Please try again."
                    )
                    print(colored(msg, "red"))
                    attempts += 1
                    password = None
                    continue

                key = derive_index_key(self.parent_seed)

                self.encryption_manager = EncryptionManager(key, fingerprint_dir)
                self.vault = Vault(self.encryption_manager, fingerprint_dir)

                self.config_manager = ConfigManager(
                    vault=self.vault,
                    fingerprint_dir=fingerprint_dir,
                )

                self.fingerprint_dir = fingerprint_dir
                if not self.verify_password(password):
                    print(colored("Invalid password. Please try again.", "red"))
                    attempts += 1
                    password = None
                    continue
                return True
            except KeyboardInterrupt:
                raise
            except Exception as e:
                logger.error(f"Failed to set up EncryptionManager: {e}", exc_info=True)
                print(colored(f"Error: Failed to set up encryption: {e}", "red"))
                if exit_on_fail:
                    sys.exit(1)
                return False
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
            mode = (
                self.config_manager.get_kdf_mode()
                if getattr(self, "config_manager", None)
                else "pbkdf2"
            )
            iterations = (
                self.config_manager.get_kdf_iterations()
                if getattr(self, "config_manager", None)
                else 50_000
            )
            if mode == "argon2":
                seed_key = derive_key_from_password_argon2(password)
            else:
                seed_key = derive_key_from_password(password, iterations=iterations)
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
            self.start_background_sync()
            print(colored(f"Switched to seed profile {selected_fingerprint}.", "green"))

            # Re-initialize NostrClient with the new fingerprint
            try:
                self.nostr_client = NostrClient(
                    encryption_manager=self.encryption_manager,
                    fingerprint=self.current_fingerprint,
                    config_manager=getattr(self, "config_manager", None),
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

    def load_managed_account(self, index: int) -> None:
        """Load a managed account derived from the current seed profile."""
        if not self.entry_manager or not self.parent_seed:
            raise ValueError("Manager not initialized")

        seed = self.entry_manager.get_managed_account_seed(index, self.parent_seed)
        managed_fp = generate_fingerprint(seed)
        account_dir = self.fingerprint_dir / "accounts" / managed_fp
        account_dir.mkdir(parents=True, exist_ok=True)

        self.profile_stack.append(
            (self.current_fingerprint, self.fingerprint_dir, self.parent_seed)
        )

        self.current_fingerprint = managed_fp
        self.fingerprint_dir = account_dir
        self.parent_seed = seed

        key = derive_index_key(seed)
        self.encryption_manager = EncryptionManager(key, account_dir)
        self.vault = Vault(self.encryption_manager, account_dir)

        self.initialize_bip85()
        self.initialize_managers()
        self.locked = False
        self.update_activity()
        self.start_background_sync()

    def exit_managed_account(self) -> None:
        """Return to the parent seed profile if one is on the stack."""
        if not self.profile_stack:
            return
        fp, path, seed = self.profile_stack.pop()

        self.current_fingerprint = fp
        self.fingerprint_dir = path
        self.parent_seed = seed

        key = derive_index_key(seed)
        self.encryption_manager = EncryptionManager(key, path)
        self.vault = Vault(self.encryption_manager, path)

        self.initialize_bip85()
        self.initialize_managers()
        self.locked = False
        self.update_activity()
        self.start_background_sync()

    def handle_existing_seed(self) -> None:
        """
        Handles the scenario where an existing parent seed file is found.
        Prompts the user for the master password to decrypt the seed.
        """
        try:
            # Prompt for password
            password = getpass.getpass(prompt="Enter your login password: ").strip()

            # Derive encryption key from password
            iterations = (
                self.config_manager.get_kdf_iterations()
                if getattr(self, "config_manager", None)
                else 50_000
            )
            key = derive_key_from_password(password, iterations=iterations)

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

                try:
                    # Initialize EncryptionManager with key and fingerprint_dir
                    password = prompt_for_password()
                    index_key = derive_index_key(parent_seed)
                    iterations = (
                        self.config_manager.get_kdf_iterations()
                        if getattr(self, "config_manager", None)
                        else 50_000
                    )
                    seed_key = derive_key_from_password(password, iterations=iterations)

                    self.encryption_manager = EncryptionManager(
                        index_key, fingerprint_dir
                    )
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
                    self.start_background_sync()
                    return fingerprint  # Return the generated or added fingerprint
                except BaseException:
                    # Clean up partial profile on failure or interruption
                    self.fingerprint_manager.remove_fingerprint(fingerprint)
                    raise
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
            try:
                self.save_and_encrypt_seed(new_seed, fingerprint_dir)
                self.start_background_sync()
            except BaseException:
                # Clean up partial profile on failure or interruption
                self.fingerprint_manager.remove_fingerprint(fingerprint)
                raise

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
            iterations = (
                self.config_manager.get_kdf_iterations()
                if getattr(self, "config_manager", None)
                else 50_000
            )
            seed_key = derive_key_from_password(password, iterations=iterations)

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
            self.config_manager = ConfigManager(
                vault=self.vault,
                fingerprint_dir=self.fingerprint_dir,
            )
            self.backup_manager = BackupManager(
                fingerprint_dir=self.fingerprint_dir,
                config_manager=self.config_manager,
            )
            self.entry_manager = EntryManager(
                vault=self.vault,
                backup_manager=self.backup_manager,
            )

            self.password_generator = PasswordGenerator(
                encryption_manager=self.encryption_manager,
                parent_seed=self.parent_seed,
                bip85=self.bip85,
                policy=self.config_manager.get_password_policy(),
            )

            # Load relay configuration and initialize NostrClient
            config = self.config_manager.load_config()
            relay_list = config.get("relays", list(DEFAULT_RELAYS))
            self.offline_mode = bool(config.get("offline_mode", False))
            self.inactivity_timeout = config.get(
                "inactivity_timeout", INACTIVITY_TIMEOUT
            )
            self.secret_mode_enabled = bool(config.get("secret_mode_enabled", False))
            self.clipboard_clear_delay = int(config.get("clipboard_clear_delay", 45))
            self.verbose_timing = bool(config.get("verbose_timing", False))
            if not self.offline_mode:
                print("Connecting to relays...")
            self.nostr_client = NostrClient(
                encryption_manager=self.encryption_manager,
                fingerprint=self.current_fingerprint,
                relays=relay_list,
                offline_mode=self.offline_mode,
                config_manager=self.config_manager,
                parent_seed=getattr(self, "parent_seed", None),
            )

            logger.debug("Managers re-initialized for the new fingerprint.")

        except Exception as e:
            logger.error(f"Failed to initialize managers: {e}", exc_info=True)
            print(colored(f"Error: Failed to initialize managers: {e}", "red"))
            sys.exit(1)

    def sync_index_from_nostr(self) -> None:
        """Always fetch the latest vault data from Nostr and update the local index."""
        start = time.perf_counter()
        try:
            result = asyncio.run(self.nostr_client.fetch_latest_snapshot())
            if not result:
                return
            manifest, chunks = result
            encrypted = gzip.decompress(b"".join(chunks))
            if manifest.delta_since:
                version = int(manifest.delta_since)
                deltas = asyncio.run(self.nostr_client.fetch_deltas_since(version))
                if deltas:
                    encrypted = deltas[-1]
            current = self.vault.get_encrypted_index()
            if current != encrypted:
                self.vault.decrypt_and_save_index_from_nostr(encrypted)
                logger.info("Local database synchronized from Nostr.")
        except Exception as e:
            logger.warning(f"Unable to sync index from Nostr: {e}")
        finally:
            if getattr(self, "verbose_timing", False):
                duration = time.perf_counter() - start
                logger.info("sync_index_from_nostr completed in %.2f seconds", duration)

    def start_background_sync(self) -> None:
        """Launch a thread to synchronize the vault without blocking the UI."""
        if getattr(self, "offline_mode", False):
            return
        if (
            hasattr(self, "_sync_thread")
            and self._sync_thread
            and self._sync_thread.is_alive()
        ):
            return

        def _worker() -> None:
            try:
                if hasattr(self, "nostr_client") and hasattr(self, "vault"):
                    self.sync_index_from_nostr_if_missing()
                if hasattr(self, "sync_index_from_nostr"):
                    self.sync_index_from_nostr()
            except Exception as exc:
                logger.warning(f"Background sync failed: {exc}")

        self._sync_thread = threading.Thread(target=_worker, daemon=True)
        self._sync_thread.start()

    def start_background_relay_check(self) -> None:
        """Check relay health in a background thread."""
        if (
            hasattr(self, "_relay_thread")
            and self._relay_thread
            and self._relay_thread.is_alive()
        ):
            return

        def _worker() -> None:
            try:
                if getattr(self, "nostr_client", None) and hasattr(
                    self.nostr_client, "check_relay_health"
                ):
                    healthy = self.nostr_client.check_relay_health(MIN_HEALTHY_RELAYS)
                    if healthy < MIN_HEALTHY_RELAYS:
                        self.notify(
                            f"Only {healthy} relay(s) responded with your latest event. "
                            "Consider adding more relays via Settings.",
                            level="WARNING",
                        )
            except Exception as exc:
                logger.warning(f"Relay health check failed: {exc}")

        self._relay_thread = threading.Thread(target=_worker, daemon=True)
        self._relay_thread.start()

    def start_background_vault_sync(self, alt_summary: str | None = None) -> None:
        """Publish the vault to Nostr in a background thread."""
        if getattr(self, "offline_mode", False):
            return

        def _worker() -> None:
            try:
                self.sync_vault(alt_summary=alt_summary)
            except Exception as exc:
                logging.error(f"Background vault sync failed: {exc}", exc_info=True)

        threading.Thread(target=_worker, daemon=True).start()

    def sync_index_from_nostr_if_missing(self) -> None:
        """Retrieve the password database from Nostr if it doesn't exist locally.

        If no valid data is found or decryption fails, initialize a fresh local
        database and publish it to Nostr.
        """
        index_file = self.fingerprint_dir / "seedpass_entries_db.json.enc"
        if index_file.exists():
            return
        have_data = False
        try:
            result = asyncio.run(self.nostr_client.fetch_latest_snapshot())
            if result:
                manifest, chunks = result
                encrypted = gzip.decompress(b"".join(chunks))
                if manifest.delta_since:
                    version = int(manifest.delta_since)
                    deltas = asyncio.run(self.nostr_client.fetch_deltas_since(version))
                    if deltas:
                        encrypted = deltas[-1]
                try:
                    self.vault.decrypt_and_save_index_from_nostr(encrypted)
                    logger.info("Initialized local database from Nostr.")
                    have_data = True
                except Exception as err:
                    logger.warning(
                        f"Failed to decrypt Nostr data: {err}; treating as new account."
                    )
        except Exception as e:
            logger.warning(f"Unable to sync index from Nostr: {e}")

        if not have_data:
            self.vault.save_index({"schema_version": LATEST_VERSION, "entries": {}})
            try:
                self.sync_vault()
            except Exception as exc:  # pragma: no cover - best effort
                logger.warning(f"Unable to publish fresh database: {exc}")

    def handle_add_password(self) -> None:
        try:
            fp, parent_fp, child_fp = self.header_fingerprint_args
            clear_and_print_fingerprint(
                fp,
                "Main Menu > Add Entry > Password",
                parent_fingerprint=parent_fp,
                child_fingerprint=child_fp,
            )
            website_name = input("Enter the label or website name: ").strip()
            if not website_name:
                print(colored("Error: Label cannot be empty.", "red"))
                return

            username = input("Enter the username (optional): ").strip()
            url = input("Enter the URL (optional): ").strip()
            notes = input("Enter notes (optional): ").strip()
            tags_input = input("Enter tags (comma-separated, optional): ").strip()
            tags = (
                [t.strip() for t in tags_input.split(",") if t.strip()]
                if tags_input
                else []
            )

            custom_fields: list[dict[str, object]] = []
            while True:
                add_field = input("Add custom field? (y/N): ").strip().lower()
                if add_field != "y":
                    break
                label = input("  Field label: ").strip()
                value = input("  Field value: ").strip()
                hidden = input("  Hidden field? (y/N): ").strip().lower() == "y"
                custom_fields.append(
                    {"label": label, "value": value, "is_hidden": hidden}
                )

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
                archived=False,
                notes=notes,
                custom_fields=custom_fields,
                tags=tags,
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
                self.start_background_vault_sync()
                logging.info("Encrypted index posted to Nostr after entry addition.")
            except Exception as nostr_error:
                logging.error(
                    f"Failed to post updated index to Nostr: {nostr_error}",
                    exc_info=True,
                )
            pause()

        except Exception as e:
            logging.error(f"Error during password generation: {e}", exc_info=True)
            print(colored(f"Error: Failed to generate password: {e}", "red"))
            pause()

    def handle_add_totp(self) -> None:
        """Add a TOTP entry either derived from the seed or imported."""
        try:
            fp, parent_fp, child_fp = self.header_fingerprint_args
            clear_and_print_fingerprint(
                fp,
                "Main Menu > Add Entry > 2FA (TOTP)",
                parent_fingerprint=parent_fp,
                child_fingerprint=child_fp,
            )
            while True:
                print("\nAdd TOTP:")
                print("1. Make 2FA (derive from seed)")
                print("2. Import 2FA (paste otpauth URI or secret)")
                choice = input("Select option or press Enter to go back: ").strip()
                if choice == "1":
                    label = input("Label: ").strip()
                    if not label:
                        print(colored("Error: Label cannot be empty.", "red"))
                        continue
                    period = input("Period (default 30): ").strip() or "30"
                    digits = input("Digits (default 6): ").strip() or "6"
                    if not period.isdigit() or not digits.isdigit():
                        print(
                            colored("Error: Period and digits must be numbers.", "red")
                        )
                        continue
                    notes = input("Notes (optional): ").strip()
                    tags_input = input(
                        "Enter tags (comma-separated, optional): "
                    ).strip()
                    tags = (
                        [t.strip() for t in tags_input.split(",") if t.strip()]
                        if tags_input
                        else []
                    )
                    totp_index = self.entry_manager.get_next_totp_index()
                    entry_id = self.entry_manager.get_next_index()
                    uri = self.entry_manager.add_totp(
                        label,
                        self.parent_seed,
                        index=totp_index,
                        period=int(period),
                        digits=int(digits),
                        notes=notes,
                        tags=tags,
                    )
                    secret = TotpManager.derive_secret(self.parent_seed, totp_index)
                    self.is_dirty = True
                    self.last_update = time.time()
                    print(
                        colored(
                            f"\n[+] TOTP entry added with ID {entry_id}.\n", "green"
                        )
                    )
                    print(colored("Add this URI to your authenticator app:", "cyan"))
                    print(colored(uri, "yellow"))
                    TotpManager.print_qr_code(uri)
                    print(color_text(f"Secret: {secret}\n", "deterministic"))
                    try:
                        self.start_background_vault_sync()
                    except Exception as nostr_error:
                        logging.error(
                            f"Failed to post updated index to Nostr: {nostr_error}",
                            exc_info=True,
                        )
                    pause()
                    break
                elif choice == "2":
                    raw = input("Paste otpauth URI or secret: ").strip()
                    try:
                        if raw.lower().startswith("otpauth://"):
                            label, secret, period, digits = TotpManager.parse_otpauth(
                                raw
                            )
                        else:
                            label = input("Label: ").strip()
                            secret = raw.upper()
                            period = int(input("Period (default 30): ").strip() or 30)
                            digits = int(input("Digits (default 6): ").strip() or 6)
                        notes = input("Notes (optional): ").strip()
                        tags_input = input(
                            "Enter tags (comma-separated, optional): "
                        ).strip()
                        tags = (
                            [t.strip() for t in tags_input.split(",") if t.strip()]
                            if tags_input
                            else []
                        )
                        entry_id = self.entry_manager.get_next_index()
                        uri = self.entry_manager.add_totp(
                            label,
                            self.parent_seed,
                            secret=secret,
                            period=period,
                            digits=digits,
                            notes=notes,
                            tags=tags,
                        )
                        self.is_dirty = True
                        self.last_update = time.time()
                        print(
                            colored(
                                f"\nImported \u2714  Codes for {label} are now stored in SeedPass at ID {entry_id}.",
                                "green",
                            )
                        )
                        TotpManager.print_qr_code(uri)
                        try:
                            self.start_background_vault_sync()
                        except Exception as nostr_error:
                            logging.error(
                                f"Failed to post updated index to Nostr: {nostr_error}",
                                exc_info=True,
                            )
                        pause()
                        break
                    except ValueError as err:
                        print(colored(f"Error: {err}", "red"))
                elif not choice:
                    return
                else:
                    print(colored("Invalid choice.", "red"))
        except Exception as e:
            logging.error(f"Error during TOTP setup: {e}", exc_info=True)
            print(colored(f"Error: Failed to add TOTP: {e}", "red"))
            pause()

    def handle_add_ssh_key(self) -> None:
        """Add an SSH key pair entry and display the derived keys."""
        try:
            fp, parent_fp, child_fp = self.header_fingerprint_args
            clear_and_print_fingerprint(
                fp,
                "Main Menu > Add Entry > SSH Key",
                parent_fingerprint=parent_fp,
                child_fingerprint=child_fp,
            )
            label = input("Label: ").strip()
            if not label:
                print(colored("Error: Label cannot be empty.", "red"))
                return
            notes = input("Notes (optional): ").strip()
            tags_input = input("Enter tags (comma-separated, optional): ").strip()
            tags = (
                [t.strip() for t in tags_input.split(",") if t.strip()]
                if tags_input
                else []
            )
            index = self.entry_manager.add_ssh_key(
                label, self.parent_seed, notes=notes, tags=tags
            )
            priv_pem, pub_pem = self.entry_manager.get_ssh_key_pair(
                index, self.parent_seed
            )
            self.is_dirty = True
            self.last_update = time.time()

            if not confirm_action(
                "WARNING: Displaying SSH keys reveals sensitive information. Continue? (Y/N): "
            ):
                print(colored("SSH key display cancelled.", "yellow"))
                return

            print(colored(f"\n[+] SSH key entry added with ID {index}.\n", "green"))
            if notes:
                print(colored(f"Notes: {notes}", "cyan"))
            print(colored("Public Key:", "cyan"))
            print(color_text(pub_pem, "default"))
            print(colored("Private Key:", "cyan"))
            print(color_text(priv_pem, "deterministic"))
            try:
                self.start_background_vault_sync()
            except Exception as nostr_error:
                logging.error(
                    f"Failed to post updated index to Nostr: {nostr_error}",
                    exc_info=True,
                )
            pause()
        except Exception as e:
            logging.error(f"Error during SSH key setup: {e}", exc_info=True)
            print(colored(f"Error: Failed to add SSH key: {e}", "red"))
            pause()

    def handle_add_seed(self) -> None:
        """Add a derived BIP-39 seed phrase entry."""
        try:
            fp, parent_fp, child_fp = self.header_fingerprint_args
            clear_and_print_fingerprint(
                fp,
                "Main Menu > Add Entry > Seed Phrase",
                parent_fingerprint=parent_fp,
                child_fingerprint=child_fp,
            )
            label = input("Label: ").strip()
            if not label:
                print(colored("Error: Label cannot be empty.", "red"))
                return
            words_input = input("Word count (12 or 24, default 24): ").strip()
            notes = input("Notes (optional): ").strip()
            tags_input = input("Enter tags (comma-separated, optional): ").strip()
            tags = (
                [t.strip() for t in tags_input.split(",") if t.strip()]
                if tags_input
                else []
            )
            if words_input and words_input not in {"12", "24"}:
                print(colored("Invalid word count. Choose 12 or 24.", "red"))
                return
            words = int(words_input) if words_input else 24
            index = self.entry_manager.add_seed(
                label, self.parent_seed, words_num=words, notes=notes, tags=tags
            )
            phrase = self.entry_manager.get_seed_phrase(index, self.parent_seed)
            self.is_dirty = True
            self.last_update = time.time()

            if not confirm_action(
                "WARNING: Displaying the seed phrase reveals sensitive information. Continue? (Y/N): "
            ):
                print(colored("Seed phrase display cancelled.", "yellow"))
                return

            print(
                colored(
                    f"\n[+] Seed entry '{label}' added with ID {index}.\n",
                    "green",
                )
            )
            print(colored(f"Index: {index}", "cyan"))
            print(colored(f"Label: {label}", "cyan"))
            if notes:
                print(colored(f"Notes: {notes}", "cyan"))
            print(colored("Seed Phrase:", "cyan"))
            print(color_text(phrase, "deterministic"))
            if confirm_action("Show Compact Seed QR? (Y/N): "):
                from password_manager.seedqr import encode_seedqr

                TotpManager.print_qr_code(encode_seedqr(phrase))
            try:
                self.start_background_vault_sync()
            except Exception as nostr_error:
                logging.error(
                    f"Failed to post updated index to Nostr: {nostr_error}",
                    exc_info=True,
                )
            pause()
        except Exception as e:
            logging.error(f"Error during seed phrase setup: {e}", exc_info=True)
            print(colored(f"Error: Failed to add seed phrase: {e}", "red"))
            pause()

    def handle_add_pgp(self) -> None:
        """Add a PGP key entry and display the generated key."""
        try:
            fp, parent_fp, child_fp = self.header_fingerprint_args
            clear_and_print_fingerprint(
                fp,
                "Main Menu > Add Entry > PGP Key",
                parent_fingerprint=parent_fp,
                child_fingerprint=child_fp,
            )
            label = input("Label: ").strip()
            if not label:
                print(colored("Error: Label cannot be empty.", "red"))
                return
            key_type = (
                input("Key type (ed25519 or rsa, default ed25519): ").strip().lower()
                or "ed25519"
            )
            user_id = input("User ID (optional): ").strip()
            notes = input("Notes (optional): ").strip()
            tags_input = input("Enter tags (comma-separated, optional): ").strip()
            tags = (
                [t.strip() for t in tags_input.split(",") if t.strip()]
                if tags_input
                else []
            )
            index = self.entry_manager.add_pgp_key(
                label,
                self.parent_seed,
                key_type=key_type,
                user_id=user_id,
                notes=notes,
                tags=tags,
            )
            priv_key, fingerprint = self.entry_manager.get_pgp_key(
                index, self.parent_seed
            )
            self.is_dirty = True
            self.last_update = time.time()

            if not confirm_action(
                "WARNING: Displaying the PGP key reveals sensitive information. Continue? (Y/N): "
            ):
                print(colored("PGP key display cancelled.", "yellow"))
                return

            print(colored(f"\n[+] PGP key entry added with ID {index}.\n", "green"))
            if user_id:
                print(colored(f"User ID: {user_id}", "cyan"))
            if notes:
                print(colored(f"Notes: {notes}", "cyan"))
            print(colored(f"Fingerprint: {fingerprint}", "cyan"))
            print(color_text(priv_key, "deterministic"))
            try:
                self.start_background_vault_sync()
            except Exception as nostr_error:  # pragma: no cover - best effort
                logging.error(
                    f"Failed to post updated index to Nostr: {nostr_error}",
                    exc_info=True,
                )
            pause()
        except Exception as e:
            logging.error(f"Error during PGP key setup: {e}", exc_info=True)
            print(colored(f"Error: Failed to add PGP key: {e}", "red"))
            pause()

    def handle_add_nostr_key(self) -> None:
        """Add a Nostr key entry and display the derived keys."""
        try:
            fp, parent_fp, child_fp = self.header_fingerprint_args
            clear_and_print_fingerprint(
                fp,
                "Main Menu > Add Entry > Nostr Key Pair",
                parent_fingerprint=parent_fp,
                child_fingerprint=child_fp,
            )
            label = input("Label: ").strip()
            if not label:
                print(colored("Error: Label cannot be empty.", "red"))
                return
            notes = input("Notes (optional): ").strip()
            tags_input = input("Enter tags (comma-separated, optional): ").strip()
            tags = (
                [t.strip() for t in tags_input.split(",") if t.strip()]
                if tags_input
                else []
            )
            index = self.entry_manager.add_nostr_key(label, notes=notes, tags=tags)
            npub, nsec = self.entry_manager.get_nostr_key_pair(index, self.parent_seed)
            self.is_dirty = True
            self.last_update = time.time()
            print(colored(f"\n[+] Nostr key entry added with ID {index}.\n", "green"))
            print(colored(f"npub: {npub}", "cyan"))
            if self.secret_mode_enabled:
                copy_to_clipboard(nsec, self.clipboard_clear_delay)
                print(
                    colored(
                        f"[+] nsec copied to clipboard. Will clear in {self.clipboard_clear_delay} seconds.",
                        "green",
                    )
                )
            else:
                print(color_text(f"nsec: {nsec}", "deterministic"))
            if confirm_action("Show QR code for npub? (Y/N): "):
                TotpManager.print_qr_code(f"nostr:{npub}")
            if confirm_action(
                "WARNING: Displaying the nsec QR reveals your private key. Continue? (Y/N): "
            ):
                TotpManager.print_qr_code(nsec)
            try:
                self.start_background_vault_sync()
            except Exception as nostr_error:  # pragma: no cover - best effort
                logging.error(
                    f"Failed to post updated index to Nostr: {nostr_error}",
                    exc_info=True,
                )
            pause()
        except Exception as e:
            logging.error(f"Error during Nostr key setup: {e}", exc_info=True)
            print(colored(f"Error: Failed to add Nostr key: {e}", "red"))
            pause()

    def handle_add_key_value(self) -> None:
        """Add a generic key/value entry."""
        try:
            fp, parent_fp, child_fp = self.header_fingerprint_args
            clear_and_print_fingerprint(
                fp,
                "Main Menu > Add Entry > Key/Value",
                parent_fingerprint=parent_fp,
                child_fingerprint=child_fp,
            )
            label = input("Label: ").strip()
            if not label:
                print(colored("Error: Label cannot be empty.", "red"))
                return
            value = input("Value: ").strip()
            notes = input("Notes (optional): ").strip()
            tags_input = input("Enter tags (comma-separated, optional): ").strip()
            tags = (
                [t.strip() for t in tags_input.split(",") if t.strip()]
                if tags_input
                else []
            )

            custom_fields: list[dict[str, object]] = []
            while True:
                add_field = input("Add custom field? (y/N): ").strip().lower()
                if add_field != "y":
                    break
                field_label = input("  Field label: ").strip()
                field_value = input("  Field value: ").strip()
                hidden = input("  Hidden field? (y/N): ").strip().lower() == "y"
                custom_fields.append(
                    {
                        "label": field_label,
                        "value": field_value,
                        "is_hidden": hidden,
                    }
                )

            index = self.entry_manager.add_key_value(
                label,
                value,
                notes=notes,
                custom_fields=custom_fields,
                tags=tags,
            )
            self.is_dirty = True
            self.last_update = time.time()

            print(colored(f"\n[+] Key/Value entry added with ID {index}.\n", "green"))
            if notes:
                print(colored(f"Notes: {notes}", "cyan"))
            if self.secret_mode_enabled:
                copy_to_clipboard(value, self.clipboard_clear_delay)
                print(
                    colored(
                        f"[+] Value copied to clipboard. Will clear in {self.clipboard_clear_delay} seconds.",
                        "green",
                    )
                )
            else:
                print(color_text(f"Value: {value}", "deterministic"))
            try:
                self.start_background_vault_sync()
            except Exception as nostr_error:  # pragma: no cover - best effort
                logging.error(
                    f"Failed to post updated index to Nostr: {nostr_error}",
                    exc_info=True,
                )
            pause()
        except Exception as e:
            logging.error(f"Error during key/value setup: {e}", exc_info=True)
            print(colored(f"Error: Failed to add key/value entry: {e}", "red"))
            pause()

    def handle_add_managed_account(self) -> None:
        """Add a managed account seed entry."""
        try:
            fp, parent_fp, child_fp = self.header_fingerprint_args
            clear_and_print_fingerprint(
                fp,
                "Main Menu > Add Entry > Managed Account",
                parent_fingerprint=parent_fp,
                child_fingerprint=child_fp,
            )
            label = input("Label: ").strip()
            if not label:
                print(colored("Error: Label cannot be empty.", "red"))
                return
            notes = input("Notes (optional): ").strip()
            tags_input = input("Enter tags (comma-separated, optional): ").strip()
            tags = (
                [t.strip() for t in tags_input.split(",") if t.strip()]
                if tags_input
                else []
            )
            index = self.entry_manager.add_managed_account(
                label, self.parent_seed, notes=notes, tags=tags
            )
            seed = self.entry_manager.get_managed_account_seed(index, self.parent_seed)
            self.is_dirty = True
            self.last_update = time.time()
            print(
                colored(
                    f"\n[+] Managed account '{label}' added with ID {index}.\n",
                    "green",
                )
            )
            if confirm_action("Reveal seed now? (y/N): "):
                if self.secret_mode_enabled:
                    copy_to_clipboard(seed, self.clipboard_clear_delay)
                    print(
                        colored(
                            f"[+] Seed copied to clipboard. Will clear in {self.clipboard_clear_delay} seconds.",
                            "green",
                        )
                    )
                else:
                    print(color_text(seed, "deterministic"))
                if confirm_action("Show Compact Seed QR? (Y/N): "):
                    from password_manager.seedqr import encode_seedqr

                    TotpManager.print_qr_code(encode_seedqr(seed))
            try:
                self.start_background_vault_sync()
            except Exception as nostr_error:  # pragma: no cover - best effort
                logging.error(
                    f"Failed to post updated index to Nostr: {nostr_error}",
                    exc_info=True,
                )
            pause()
        except Exception as e:
            logging.error(f"Error during managed account setup: {e}", exc_info=True)
            print(colored(f"Error: Failed to add managed account: {e}", "red"))
            pause()

    def show_entry_details_by_index(self, index: int) -> None:
        """Display entry details using :meth:`handle_retrieve_entry` for the
        given index without prompting for it again."""

        original_input = builtins.input
        first_call = True

        def patched_input(prompt: str = "") -> str:
            nonlocal first_call
            if first_call:
                first_call = False
                return str(index)
            return original_input(prompt)

        try:
            builtins.input = patched_input
            self.handle_retrieve_entry()
        finally:
            builtins.input = original_input

    def _prompt_toggle_archive(self, entry: dict, index: int) -> None:
        """Prompt the user to archive or restore ``entry`` based on its status."""
        archived = entry.get("archived", entry.get("blacklisted", False))
        prompt = (
            "Restore this entry from archive? (y/N): "
            if archived
            else "Archive this entry? (y/N): "
        )
        choice = input(prompt).strip().lower()
        if choice == "y":
            if archived:
                self.entry_manager.restore_entry(index)
            else:
                self.entry_manager.archive_entry(index)
            self.is_dirty = True
            self.last_update = time.time()

    def _entry_actions_menu(self, index: int, entry: dict) -> None:
        """Provide actions for a retrieved entry."""
        while True:
            archived = entry.get("archived", entry.get("blacklisted", False))
            entry_type = entry.get("type", EntryType.PASSWORD.value)
            print(colored("\n[+] Entry Actions:", "green"))
            if archived:
                print(colored("U. Unarchive", "cyan"))
            else:
                print(colored("A. Archive", "cyan"))
            print(colored("N. Add Note", "cyan"))
            print(colored("C. Add Custom Field", "cyan"))
            print(colored("H. Add Hidden Field", "cyan"))
            print(colored("E. Edit", "cyan"))
            print(colored("T. Edit Tags", "cyan"))
            if entry_type in {
                EntryType.SEED.value,
                EntryType.MANAGED_ACCOUNT.value,
                EntryType.NOSTR.value,
            }:
                print(colored("Q. Show QR codes", "cyan"))

            choice = (
                input("Select an action or press Enter to return: ").strip().lower()
            )
            if not choice:
                break
            if choice == "a" and not archived:
                self.entry_manager.archive_entry(index)
                self.is_dirty = True
                self.last_update = time.time()
            elif choice == "u" and archived:
                self.entry_manager.restore_entry(index)
                self.is_dirty = True
                self.last_update = time.time()
            elif choice == "n":
                note = input("Enter note: ").strip()
                if note:
                    notes = entry.get("notes", "")
                    notes = f"{notes}\n{note}" if notes else note
                    self.entry_manager.modify_entry(index, notes=notes)
                    self.is_dirty = True
                    self.last_update = time.time()
            elif choice in {"c", "h"}:
                label = input("  Field label: ").strip()
                if not label:
                    print(colored("Field label cannot be empty.", "red"))
                else:
                    value = input("  Field value: ").strip()
                    hidden = choice == "h"
                    custom_fields = entry.get("custom_fields", [])
                    custom_fields.append(
                        {"label": label, "value": value, "is_hidden": hidden}
                    )
                    self.entry_manager.modify_entry(index, custom_fields=custom_fields)
                    self.is_dirty = True
                    self.last_update = time.time()
            elif choice == "t":
                current_tags = entry.get("tags", [])
                print(
                    colored(
                        f"Current tags: {', '.join(current_tags) if current_tags else 'None'}",
                        "cyan",
                    )
                )
                tags_input = input(
                    "Enter tags (comma-separated, leave blank to remove all tags): "
                ).strip()
                tags = (
                    [t.strip() for t in tags_input.split(",") if t.strip()]
                    if tags_input
                    else []
                )
                self.entry_manager.modify_entry(index, tags=tags)
                self.is_dirty = True
                self.last_update = time.time()
            elif choice == "e":
                self._entry_edit_menu(index, entry)
            elif choice == "q":
                self._entry_qr_menu(index, entry)
            else:
                print(colored("Invalid choice.", "red"))
            entry = self.entry_manager.retrieve_entry(index) or entry

    def _entry_edit_menu(self, index: int, entry: dict) -> None:
        """Sub-menu for editing common entry fields."""
        entry_type = entry.get("type", EntryType.PASSWORD.value)
        while True:
            print(colored("\n[+] Edit Menu:", "green"))
            print(colored("L. Edit Label", "cyan"))
            if entry_type == EntryType.PASSWORD.value:
                print(colored("U. Edit Username", "cyan"))
                print(colored("R. Edit URL", "cyan"))
            elif entry_type == EntryType.TOTP.value:
                print(colored("P. Edit Period", "cyan"))
                print(colored("D. Edit Digits", "cyan"))
            choice = input("Select option or press Enter to go back: ").strip().lower()
            if not choice:
                break
            if choice == "l":
                new_label = input("New label: ").strip()
                if new_label:
                    self.entry_manager.modify_entry(index, label=new_label)
                    self.is_dirty = True
                    self.last_update = time.time()
            elif entry_type == EntryType.PASSWORD.value and choice == "u":
                new_username = input("New username: ").strip()
                self.entry_manager.modify_entry(index, username=new_username)
                self.is_dirty = True
                self.last_update = time.time()
            elif entry_type == EntryType.PASSWORD.value and choice == "r":
                new_url = input("New URL: ").strip()
                self.entry_manager.modify_entry(index, url=new_url)
                self.is_dirty = True
                self.last_update = time.time()
            elif entry_type == EntryType.TOTP.value and choice == "p":
                period_str = input("New period (seconds): ").strip()
                if period_str.isdigit():
                    self.entry_manager.modify_entry(index, period=int(period_str))
                    self.is_dirty = True
                    self.last_update = time.time()
                else:
                    print(colored("Invalid period value.", "red"))
            elif entry_type == EntryType.TOTP.value and choice == "d":
                digits_str = input("New digits: ").strip()
                if digits_str.isdigit():
                    self.entry_manager.modify_entry(index, digits=int(digits_str))
                    self.is_dirty = True
                    self.last_update = time.time()
                else:
                    print(colored("Invalid digits value.", "red"))
            else:
                print(colored("Invalid choice.", "red"))
            entry = self.entry_manager.retrieve_entry(index) or entry

    def _entry_qr_menu(self, index: int, entry: dict) -> None:
        """Display QR codes for the given ``entry``."""

        entry_type = entry.get("type")

        try:
            if entry_type in {EntryType.SEED.value, EntryType.MANAGED_ACCOUNT.value}:
                if entry_type == EntryType.SEED.value:
                    seed = self.entry_manager.get_seed_phrase(index, self.parent_seed)
                else:
                    seed = self.entry_manager.get_managed_account_seed(
                        index, self.parent_seed
                    )

                print(color_text(seed, "deterministic"))
                from password_manager.seedqr import encode_seedqr

                TotpManager.print_qr_code(encode_seedqr(seed))
                return

            if entry_type == EntryType.NOSTR.value:
                while True:
                    print(colored("\n[+] QR Codes:", "green"))
                    print(colored("P. Public key", "cyan"))
                    print(colored("K. Private key", "cyan"))
                    choice = (
                        input("Select option or press Enter to return: ")
                        .strip()
                        .lower()
                    )
                    if not choice:
                        break

                    npub, nsec = self.entry_manager.get_nostr_key_pair(
                        index, self.parent_seed
                    )

                    if choice == "p":
                        print(colored(f"npub: {npub}", "cyan"))
                        TotpManager.print_qr_code(f"nostr:{npub}")
                    elif choice == "k":
                        print(color_text(f"nsec: {nsec}", "deterministic"))
                        TotpManager.print_qr_code(nsec)
                    else:
                        print(colored("Invalid choice.", "red"))
                    entry = self.entry_manager.retrieve_entry(index) or entry
                return

            print(colored("No QR codes available for this entry.", "yellow"))
        except Exception as e:  # pragma: no cover - best effort
            logging.error(f"Error displaying QR menu: {e}", exc_info=True)
            print(colored(f"Error: Failed to display QR codes: {e}", "red"))

    def handle_retrieve_entry(self) -> None:
        """
        Handles retrieving a password from the index by prompting the user for the index number
        and displaying the corresponding password and associated details.
        """
        try:
            fp, parent_fp, child_fp = self.header_fingerprint_args
            clear_and_print_fingerprint(
                fp,
                "Main Menu > Retrieve Entry",
                parent_fingerprint=parent_fp,
                child_fingerprint=child_fp,
            )
            index_input = input(
                "Enter the index number of the entry to retrieve: "
            ).strip()
            if not index_input.isdigit():
                print(colored("Error: Index must be a number.", "red"))
                pause()
                return
            index = int(index_input)

            entry = self.entry_manager.retrieve_entry(index)
            if not entry:
                pause()
                return

            entry_type = entry.get("type", EntryType.PASSWORD.value)

            if entry_type == EntryType.TOTP.value:
                label = entry.get("label", "")
                period = int(entry.get("period", 30))
                notes = entry.get("notes", "")
                print(colored(f"Retrieving 2FA code for '{label}'.", "cyan"))
                print(colored("Press Enter to return to the menu.", "cyan"))
                try:
                    while True:
                        code = self.entry_manager.get_totp_code(index, self.parent_seed)
                        if self.secret_mode_enabled:
                            copy_to_clipboard(code, self.clipboard_clear_delay)
                            print(
                                colored(
                                    f"[+] 2FA code for '{label}' copied to clipboard. Will clear in {self.clipboard_clear_delay} seconds.",
                                    "green",
                                )
                            )
                        else:
                            print(colored("\n[+] Retrieved 2FA Code:\n", "green"))
                            print(colored(f"Label: {label}", "cyan"))
                            imported = "secret" in entry
                            category = "imported" if imported else "deterministic"
                            print(color_text(f"Code: {code}", category))
                        if notes:
                            print(colored(f"Notes: {notes}", "cyan"))
                        tags = entry.get("tags", [])
                        if tags:
                            print(colored(f"Tags: {', '.join(tags)}", "cyan"))
                        remaining = self.entry_manager.get_totp_time_remaining(index)
                        exit_loop = False
                        while remaining > 0:
                            filled = int(20 * (period - remaining) / period)
                            bar = "[" + "#" * filled + "-" * (20 - filled) + "]"
                            sys.stdout.write(f"\r{bar} {remaining:2d}s")
                            sys.stdout.flush()
                            try:
                                user_input = timed_input("", 1)
                                if (
                                    user_input.strip() == ""
                                    or user_input.strip().lower() == "b"
                                ):
                                    exit_loop = True
                                    break
                            except TimeoutError:
                                pass
                            except KeyboardInterrupt:
                                exit_loop = True
                                print()
                                break
                            remaining -= 1
                        sys.stdout.write("\n")
                        sys.stdout.flush()
                        if exit_loop:
                            break
                except Exception as e:
                    logging.error(f"Error generating TOTP code: {e}", exc_info=True)
                    print(colored(f"Error: Failed to generate TOTP code: {e}", "red"))
                self._entry_actions_menu(index, entry)
                pause()
                return
            if entry_type == EntryType.SSH.value:
                notes = entry.get("notes", "")
                label = entry.get("label", "")
                if not confirm_action(
                    "WARNING: Displaying SSH keys reveals sensitive information. Continue? (Y/N): "
                ):
                    print(colored("SSH key display cancelled.", "yellow"))
                    return
                try:
                    priv_pem, pub_pem = self.entry_manager.get_ssh_key_pair(
                        index, self.parent_seed
                    )
                    print(colored("\n[+] Retrieved SSH Key Pair:\n", "green"))
                    if label:
                        print(colored(f"Label: {label}", "cyan"))
                    if notes:
                        print(colored(f"Notes: {notes}", "cyan"))
                    tags = entry.get("tags", [])
                    if tags:
                        print(colored(f"Tags: {', '.join(tags)}", "cyan"))
                    print(colored("Public Key:", "cyan"))
                    print(color_text(pub_pem, "default"))
                    if self.secret_mode_enabled:
                        copy_to_clipboard(priv_pem, self.clipboard_clear_delay)
                        print(
                            colored(
                                f"[+] SSH private key copied to clipboard. Will clear in {self.clipboard_clear_delay} seconds.",
                                "green",
                            )
                        )
                    else:
                        print(colored("Private Key:", "cyan"))
                        print(color_text(priv_pem, "deterministic"))
                except Exception as e:
                    logging.error(f"Error deriving SSH key pair: {e}", exc_info=True)
                    print(colored(f"Error: Failed to derive SSH keys: {e}", "red"))
                self._entry_actions_menu(index, entry)
                pause()
                return
            if entry_type == EntryType.SEED.value:
                notes = entry.get("notes", "")
                label = entry.get("label", "")
                if not confirm_action(
                    "WARNING: Displaying the seed phrase reveals sensitive information. Continue? (Y/N): "
                ):
                    print(colored("Seed phrase display cancelled.", "yellow"))
                    return
                try:
                    phrase = self.entry_manager.get_seed_phrase(index, self.parent_seed)
                    print(colored("\n[+] Retrieved Seed Phrase:\n", "green"))
                    print(colored(f"Index: {index}", "cyan"))
                    if label:
                        print(colored(f"Label: {label}", "cyan"))
                    if notes:
                        print(colored(f"Notes: {notes}", "cyan"))
                    tags = entry.get("tags", [])
                    if tags:
                        print(colored(f"Tags: {', '.join(tags)}", "cyan"))
                    if self.secret_mode_enabled:
                        copy_to_clipboard(phrase, self.clipboard_clear_delay)
                        print(
                            colored(
                                f"[+] Seed phrase copied to clipboard. Will clear in {self.clipboard_clear_delay} seconds.",
                                "green",
                            )
                        )
                    else:
                        print(color_text(phrase, "deterministic"))
                    # Removed QR code display prompt and output
                    if confirm_action("Show derived entropy as hex? (Y/N): "):
                        from local_bip85.bip85 import BIP85
                        from bip_utils import Bip39SeedGenerator

                        words = int(entry.get("word_count", entry.get("words", 24)))
                        bytes_len = {12: 16, 18: 24, 24: 32}.get(words, 32)
                        seed_bytes = Bip39SeedGenerator(self.parent_seed).Generate()
                        bip85 = BIP85(seed_bytes)
                        entropy = bip85.derive_entropy(
                            index=int(entry.get("index", index)),
                            bytes_len=bytes_len,
                            app_no=39,
                            words_len=words,
                        )
                        print(color_text(f"Entropy: {entropy.hex()}", "deterministic"))
                except Exception as e:
                    logging.error(f"Error deriving seed phrase: {e}", exc_info=True)
                    print(colored(f"Error: Failed to derive seed phrase: {e}", "red"))
                self._entry_actions_menu(index, entry)
                pause()
                return
            if entry_type == EntryType.PGP.value:
                notes = entry.get("notes", "")
                label = entry.get("user_id", "")
                if not confirm_action(
                    "WARNING: Displaying the PGP key reveals sensitive information. Continue? (Y/N): "
                ):
                    print(colored("PGP key display cancelled.", "yellow"))
                    return
                try:
                    priv_key, fingerprint = self.entry_manager.get_pgp_key(
                        index, self.parent_seed
                    )
                    print(colored("\n[+] Retrieved PGP Key:\n", "green"))
                    if label:
                        print(colored(f"User ID: {label}", "cyan"))
                    if notes:
                        print(colored(f"Notes: {notes}", "cyan"))
                    tags = entry.get("tags", [])
                    if tags:
                        print(colored(f"Tags: {', '.join(tags)}", "cyan"))
                    print(colored(f"Fingerprint: {fingerprint}", "cyan"))
                    if self.secret_mode_enabled:
                        copy_to_clipboard(priv_key, self.clipboard_clear_delay)
                        print(
                            colored(
                                f"[+] PGP key copied to clipboard. Will clear in {self.clipboard_clear_delay} seconds.",
                                "green",
                            )
                        )
                    else:
                        print(color_text(priv_key, "deterministic"))
                except Exception as e:
                    logging.error(f"Error deriving PGP key: {e}", exc_info=True)
                    print(colored(f"Error: Failed to derive PGP key: {e}", "red"))
                self._entry_actions_menu(index, entry)
                pause()
                return
            if entry_type == EntryType.NOSTR.value:
                label = entry.get("label", "")
                notes = entry.get("notes", "")
                try:
                    npub, nsec = self.entry_manager.get_nostr_key_pair(
                        index, self.parent_seed
                    )
                    print(colored("\n[+] Retrieved Nostr Keys:\n", "green"))
                    print(colored(f"Label: {label}", "cyan"))
                    print(colored(f"npub: {npub}", "cyan"))
                    if self.secret_mode_enabled:
                        copy_to_clipboard(nsec, self.clipboard_clear_delay)
                        print(
                            colored(
                                f"[+] nsec copied to clipboard. Will clear in {self.clipboard_clear_delay} seconds.",
                                "green",
                            )
                        )
                    else:
                        print(color_text(f"nsec: {nsec}", "deterministic"))
                    # QR code display removed for npub and nsec
                    if notes:
                        print(colored(f"Notes: {notes}", "cyan"))
                    tags = entry.get("tags", [])
                    if tags:
                        print(colored(f"Tags: {', '.join(tags)}", "cyan"))
                except Exception as e:
                    logging.error(f"Error deriving Nostr keys: {e}", exc_info=True)
                    print(colored(f"Error: Failed to derive Nostr keys: {e}", "red"))
                self._entry_actions_menu(index, entry)
                pause()
                return

            if entry_type == EntryType.KEY_VALUE.value:
                label = entry.get("label", "")
                value = entry.get("value", "")
                notes = entry.get("notes", "")
                archived = entry.get("archived", False)
                print(colored(f"Retrieving value for '{label}'.", "cyan"))
                if notes:
                    print(colored(f"Notes: {notes}", "cyan"))
                tags = entry.get("tags", [])
                if tags:
                    print(colored(f"Tags: {', '.join(tags)}", "cyan"))
                print(
                    colored(
                        f"Archived Status: {'Archived' if archived else 'Active'}",
                        "cyan",
                    )
                )
                if self.secret_mode_enabled:
                    copy_to_clipboard(value, self.clipboard_clear_delay)
                    print(
                        colored(
                            f"[+] Value copied to clipboard. Will clear in {self.clipboard_clear_delay} seconds.",
                            "green",
                        )
                    )
                else:
                    print(color_text(f"Value: {value}", "deterministic"))

                custom_fields = entry.get("custom_fields", [])
                if custom_fields:
                    print(colored("Additional Fields:", "cyan"))
                    hidden_fields = []
                    for field in custom_fields:
                        f_label = field.get("label", "")
                        f_value = field.get("value", "")
                        if field.get("is_hidden"):
                            hidden_fields.append((f_label, f_value))
                            print(colored(f"  {f_label}: [hidden]", "cyan"))
                        else:
                            print(colored(f"  {f_label}: {f_value}", "cyan"))
                    if hidden_fields:
                        show = input("Reveal hidden fields? (y/N): ").strip().lower()
                        if show == "y":
                            for f_label, f_value in hidden_fields:
                                if self.secret_mode_enabled:
                                    copy_to_clipboard(
                                        f_value, self.clipboard_clear_delay
                                    )
                                    print(
                                        colored(
                                            f"[+] {f_label} copied to clipboard. Will clear in {self.clipboard_clear_delay} seconds.",
                                            "green",
                                        )
                                    )
                                else:
                                    print(colored(f"  {f_label}: {f_value}", "cyan"))
                self._entry_actions_menu(index, entry)
                pause()
                return
            if entry_type == EntryType.MANAGED_ACCOUNT.value:
                label = entry.get("label", "")
                notes = entry.get("notes", "")
                archived = entry.get("archived", False)
                fingerprint = entry.get("fingerprint", "")
                print(colored(f"Managed account '{label}'.", "cyan"))
                if notes:
                    print(colored(f"Notes: {notes}", "cyan"))
                if fingerprint:
                    print(colored(f"Fingerprint: {fingerprint}", "cyan"))
                tags = entry.get("tags", [])
                if tags:
                    print(colored(f"Tags: {', '.join(tags)}", "cyan"))
                print(
                    colored(
                        f"Archived Status: {'Archived' if archived else 'Active'}",
                        "cyan",
                    )
                )
                action = (
                    input(
                        "Enter 'r' to reveal seed, 'l' to load account, or press Enter to go back: "
                    )
                    .strip()
                    .lower()
                )
                if action == "r":
                    seed = self.entry_manager.get_managed_account_seed(
                        index, self.parent_seed
                    )
                    if self.secret_mode_enabled:
                        copy_to_clipboard(seed, self.clipboard_clear_delay)
                        print(
                            colored(
                                f"[+] Seed phrase copied to clipboard. Will clear in {self.clipboard_clear_delay} seconds.",
                                "green",
                            )
                        )
                    else:
                        print(color_text(seed, "deterministic"))
                    # QR code display removed for managed account seed
                    self._entry_actions_menu(index, entry)
                    pause()
                    return
                if action == "l":
                    self.load_managed_account(index)
                    return
                self._entry_actions_menu(index, entry)
                pause()
                return

            website_name = entry.get("label", entry.get("website"))
            length = entry.get("length")
            username = entry.get("username")
            url = entry.get("url")
            blacklisted = entry.get("archived", entry.get("blacklisted"))
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
                        f"Warning: This password is archived and should not be used.",
                        "yellow",
                    )
                )

            password = self.password_generator.generate_password(length, index)

            if password:
                if self.secret_mode_enabled:
                    copy_to_clipboard(password, self.clipboard_clear_delay)
                    print(
                        colored(
                            f"[+] Password for '{website_name}' copied to clipboard. Will clear in {self.clipboard_clear_delay} seconds.",
                            "green",
                        )
                    )
                else:
                    print(
                        colored(
                            f"\n[+] Retrieved Password for {website_name}:\n",
                            "green",
                        )
                    )
                    print(color_text(f"Password: {password}", "deterministic"))
                    print(colored(f"Associated Username: {username or 'N/A'}", "cyan"))
                    print(colored(f"Associated URL: {url or 'N/A'}", "cyan"))
                    print(
                        colored(
                            f"Archived Status: {'Archived' if blacklisted else 'Active'}",
                            "cyan",
                        )
                    )
                    tags = entry.get("tags", [])
                    if tags:
                        print(colored(f"Tags: {', '.join(tags)}", "cyan"))
                    custom_fields = entry.get("custom_fields", [])
                    if custom_fields:
                        print(colored("Additional Fields:", "cyan"))
                        hidden_fields = []
                        for field in custom_fields:
                            label = field.get("label", "")
                            value = field.get("value", "")
                            if field.get("is_hidden"):
                                hidden_fields.append((label, value))
                                print(colored(f"  {label}: [hidden]", "cyan"))
                            else:
                                print(colored(f"  {label}: {value}", "cyan"))
                        if hidden_fields:
                            show = (
                                input("Reveal hidden fields? (y/N): ").strip().lower()
                            )
                            if show == "y":
                                for label, value in hidden_fields:
                                    if self.secret_mode_enabled:
                                        copy_to_clipboard(
                                            value, self.clipboard_clear_delay
                                        )
                                        print(
                                            colored(
                                                f"[+] {label} copied to clipboard. Will clear in {self.clipboard_clear_delay} seconds.",
                                                "green",
                                            )
                                        )
                                    else:
                                        print(colored(f"  {label}: {value}", "cyan"))
            else:
                print(colored("Error: Failed to retrieve the password.", "red"))
            self._entry_actions_menu(index, entry)
            pause()
        except Exception as e:
            logging.error(f"Error during password retrieval: {e}", exc_info=True)
            print(colored(f"Error: Failed to retrieve password: {e}", "red"))
            pause()

    def handle_modify_entry(self) -> None:
        """
        Handles modifying an existing password entry by prompting the user for the index number
        and new details to update.
        """
        try:
            fp, parent_fp, child_fp = self.header_fingerprint_args
            clear_and_print_fingerprint(
                fp,
                "Main Menu > Modify Entry",
                parent_fingerprint=parent_fp,
                child_fingerprint=child_fp,
            )
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

            entry_type = entry.get("type", EntryType.PASSWORD.value)

            if entry_type == EntryType.TOTP.value:
                label = entry.get("label", "")
                period = int(entry.get("period", 30))
                digits = int(entry.get("digits", 6))
                blacklisted = entry.get("archived", entry.get("blacklisted", False))
                notes = entry.get("notes", "")

                print(
                    colored(
                        f"Modifying 2FA entry '{label}' (Index: {index}):",
                        "cyan",
                    )
                )
                print(colored(f"Current Period: {period}s", "cyan"))
                print(colored(f"Current Digits: {digits}", "cyan"))
                print(
                    colored(
                        f"Current Archived Status: {'Archived' if blacklisted else 'Active'}",
                        "cyan",
                    )
                )
                new_label = (
                    input(f'Enter new label (leave blank to keep "{label}"): ').strip()
                    or label
                )
                period_input = input(
                    f"Enter new period in seconds (current: {period}): "
                ).strip()
                new_period = period
                if period_input:
                    if period_input.isdigit():
                        new_period = int(period_input)
                    else:
                        print(
                            colored("Invalid period value. Keeping current.", "yellow")
                        )
                digits_input = input(
                    f"Enter new digit count (current: {digits}): "
                ).strip()
                new_digits = digits
                if digits_input:
                    if digits_input.isdigit():
                        new_digits = int(digits_input)
                    else:
                        print(
                            colored(
                                "Invalid digits value. Keeping current.",
                                "yellow",
                            )
                        )
                blacklist_input = (
                    input(
                        f'Archive this 2FA code? (Y/N, current: {"Y" if blacklisted else "N"}): '
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
                            "Invalid input for archived status. Keeping the current status.",
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

                edit_fields = input("Edit custom fields? (y/N): ").strip().lower()
                custom_fields = None
                if edit_fields == "y":
                    custom_fields = []
                    while True:
                        label = input("  Field label (leave blank to finish): ").strip()
                        if not label:
                            break
                        value = input("  Field value: ").strip()
                        hidden = input("  Hidden field? (y/N): ").strip().lower() == "y"
                        custom_fields.append(
                            {"label": label, "value": value, "is_hidden": hidden}
                        )

                tags_input = input(
                    "Enter tags (comma-separated, leave blank to keep current): "
                ).strip()
                tags = (
                    [t.strip() for t in tags_input.split(",") if t.strip()]
                    if tags_input
                    else None
                )

                self.entry_manager.modify_entry(
                    index,
                    archived=new_blacklisted,
                    notes=new_notes,
                    label=new_label,
                    period=new_period,
                    digits=new_digits,
                    custom_fields=custom_fields,
                    tags=tags,
                )
            elif entry_type in (
                EntryType.KEY_VALUE.value,
                EntryType.MANAGED_ACCOUNT.value,
            ):
                label = entry.get("label", "")
                value = entry.get("value", "")
                blacklisted = entry.get("archived", False)
                notes = entry.get("notes", "")

                print(
                    colored(
                        f"Modifying key/value entry '{label}' (Index: {index}):",
                        "cyan",
                    )
                )
                print(
                    colored(
                        f"Current Archived Status: {'Archived' if blacklisted else 'Active'}",
                        "cyan",
                    )
                )
                new_label = (
                    input(f'Enter new label (leave blank to keep "{label}"): ').strip()
                    or label
                )
                new_value = (
                    input("Enter new value (leave blank to keep current): ").strip()
                    or value
                )
                blacklist_input = (
                    input(
                        f'Archive this entry? (Y/N, current: {"Y" if blacklisted else "N"}): '
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
                            "Invalid input for archived status. Keeping the current status.",
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

                edit_fields = input("Edit custom fields? (y/N): ").strip().lower()
                custom_fields = None
                if edit_fields == "y":
                    custom_fields = []
                    while True:
                        f_label = input(
                            "  Field label (leave blank to finish): "
                        ).strip()
                        if not f_label:
                            break
                        f_value = input("  Field value: ").strip()
                        hidden = input("  Hidden field? (y/N): ").strip().lower() == "y"
                        custom_fields.append(
                            {"label": f_label, "value": f_value, "is_hidden": hidden}
                        )

                tags_input = input(
                    "Enter tags (comma-separated, leave blank to keep current): "
                ).strip()
                tags = (
                    [t.strip() for t in tags_input.split(",") if t.strip()]
                    if tags_input
                    else None
                )

                self.entry_manager.modify_entry(
                    index,
                    archived=new_blacklisted,
                    notes=new_notes,
                    label=new_label,
                    value=new_value,
                    custom_fields=custom_fields,
                    tags=tags,
                )
            else:
                website_name = entry.get("label", entry.get("website"))
                username = entry.get("username")
                url = entry.get("url")
                blacklisted = entry.get("archived", entry.get("blacklisted"))
                notes = entry.get("notes", "")

                print(
                    colored(
                        f"Modifying entry for '{website_name}' (Index: {index}):",
                        "cyan",
                    )
                )
                print(colored(f"Current Label: {website_name}", "cyan"))
                print(colored(f"Current Username: {username or 'N/A'}", "cyan"))
                print(colored(f"Current URL: {url or 'N/A'}", "cyan"))
                print(
                    colored(
                        f"Current Archived Status: {'Archived' if blacklisted else 'Active'}",
                        "cyan",
                    )
                )

                new_label = (
                    input(
                        f'Enter new label (leave blank to keep "{website_name}"): '
                    ).strip()
                    or website_name
                )

                new_username = (
                    input(
                        f'Enter new username (leave blank to keep "{username or "N/A"}"): '
                    ).strip()
                    or username
                )
                new_url = (
                    input(
                        f'Enter new URL (leave blank to keep "{url or "N/A"}"): '
                    ).strip()
                    or url
                )
                blacklist_input = (
                    input(
                        f'Archive this password? (Y/N, current: {"Y" if blacklisted else "N"}): '
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
                            "Invalid input for archived status. Keeping the current status.",
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

                edit_fields = input("Edit custom fields? (y/N): ").strip().lower()
                custom_fields = None
                if edit_fields == "y":
                    custom_fields = []
                    while True:
                        label = input("  Field label (leave blank to finish): ").strip()
                        if not label:
                            break
                        value = input("  Field value: ").strip()
                        hidden = input("  Hidden field? (y/N): ").strip().lower() == "y"
                        custom_fields.append(
                            {"label": label, "value": value, "is_hidden": hidden}
                        )

                tags_input = input(
                    "Enter tags (comma-separated, leave blank to keep current): "
                ).strip()
                tags = (
                    [t.strip() for t in tags_input.split(",") if t.strip()]
                    if tags_input
                    else None
                )

                self.entry_manager.modify_entry(
                    index,
                    new_username,
                    new_url,
                    archived=new_blacklisted,
                    notes=new_notes,
                    label=new_label,
                    custom_fields=custom_fields,
                    tags=tags,
                )

            # Mark database as dirty for background sync
            self.is_dirty = True
            self.last_update = time.time()

            print(colored(f"Entry updated successfully for index {index}.", "green"))

            # Push the updated index to Nostr so changes are backed up.
            try:
                self.start_background_vault_sync()
                logging.info(
                    "Encrypted index posted to Nostr after entry modification."
                )
            except Exception as nostr_error:
                logging.error(
                    f"Failed to post updated index to Nostr: {nostr_error}",
                    exc_info=True,
                )

            updated_entry = self.entry_manager.retrieve_entry(index)
            if updated_entry:
                self._prompt_toggle_archive(updated_entry, index)
            pause()

        except Exception as e:
            logging.error(f"Error during modifying entry: {e}", exc_info=True)
            print(colored(f"Error: Failed to modify entry: {e}", "red"))

    def handle_search_entries(self) -> None:
        """Prompt for a query, list matches and optionally show details."""
        try:
            fp, parent_fp, child_fp = self.header_fingerprint_args
            clear_and_print_fingerprint(
                fp,
                "Main Menu > Search Entries",
                parent_fingerprint=parent_fp,
                child_fingerprint=child_fp,
            )
            query = input("Enter search string: ").strip()
            if not query:
                print(colored("No search string provided.", "yellow"))
                pause()
                return

            results = self.entry_manager.search_entries(query)
            if not results:
                print(colored("No matching entries found.", "yellow"))
                pause()
                return

            while True:
                fp, parent_fp, child_fp = self.header_fingerprint_args
                clear_and_print_fingerprint(
                    fp,
                    "Main Menu > Search Entries",
                    parent_fingerprint=parent_fp,
                    child_fingerprint=child_fp,
                )
                print(colored("\n[+] Search Results:\n", "green"))
                for idx, label, username, _url, _b in results:
                    display_label = label
                    if username:
                        display_label += f" ({username})"
                    print(colored(f"{idx}. {display_label}", "cyan"))

                idx_input = input(
                    "Enter index to view details or press Enter to go back: "
                ).strip()
                if not idx_input:
                    break
                if not idx_input.isdigit() or int(idx_input) not in [
                    r[0] for r in results
                ]:
                    print(colored("Invalid index.", "red"))
                    pause()
                    continue
                self.show_entry_details_by_index(int(idx_input))
        except Exception as e:
            logging.error(f"Failed to search entries: {e}", exc_info=True)
            print(colored(f"Error: Failed to search entries: {e}", "red"))
            pause()

    def display_entry_details(self, index: int) -> None:
        """Print detailed information for a single entry."""
        entry = self.entry_manager.retrieve_entry(index)
        if not entry:
            return

        etype = entry.get("type", entry.get("kind", EntryType.PASSWORD.value))
        print(color_text(f"Index: {index}", "index"))
        if etype == EntryType.TOTP.value:
            print(color_text(f"  Label: {entry.get('label', '')}", "index"))
            print(
                color_text(f"  Derivation Index: {entry.get('index', index)}", "index")
            )
            print(
                color_text(
                    f"  Period: {entry.get('period', 30)}s  Digits: {entry.get('digits', 6)}",
                    "index",
                )
            )
            notes = entry.get("notes", "")
            if notes:
                print(color_text(f"  Notes: {notes}", "index"))
            tags = entry.get("tags", [])
            if tags:
                print(color_text(f"  Tags: {', '.join(tags)}", "index"))
        elif etype == EntryType.SEED.value:
            print(color_text("  Type: Seed Phrase", "index"))
            print(color_text(f"  Label: {entry.get('label', '')}", "index"))
            print(color_text(f"  Words: {entry.get('words', 24)}", "index"))
            print(
                color_text(f"  Derivation Index: {entry.get('index', index)}", "index")
            )
            notes = entry.get("notes", "")
            if notes:
                print(color_text(f"  Notes: {notes}", "index"))
            tags = entry.get("tags", [])
            if tags:
                print(color_text(f"  Tags: {', '.join(tags)}", "index"))
        elif etype == EntryType.SSH.value:
            print(color_text("  Type: SSH Key", "index"))
            print(color_text(f"  Label: {entry.get('label', '')}", "index"))
            print(
                color_text(f"  Derivation Index: {entry.get('index', index)}", "index")
            )
            notes = entry.get("notes", "")
            if notes:
                print(color_text(f"  Notes: {notes}", "index"))
            tags = entry.get("tags", [])
            if tags:
                print(color_text(f"  Tags: {', '.join(tags)}", "index"))
        elif etype == EntryType.PGP.value:
            print(color_text("  Type: PGP Key", "index"))
            print(color_text(f"  Label: {entry.get('label', '')}", "index"))
            print(
                color_text(f"  Key Type: {entry.get('key_type', 'ed25519')}", "index")
            )
            uid = entry.get("user_id", "")
            if uid:
                print(color_text(f"  User ID: {uid}", "index"))
            print(
                color_text(f"  Derivation Index: {entry.get('index', index)}", "index")
            )
            notes = entry.get("notes", "")
            if notes:
                print(color_text(f"  Notes: {notes}", "index"))
            tags = entry.get("tags", [])
            if tags:
                print(color_text(f"  Tags: {', '.join(tags)}", "index"))
        elif etype == EntryType.NOSTR.value:
            print(color_text("  Type: Nostr Key", "index"))
            print(color_text(f"  Label: {entry.get('label', '')}", "index"))
            print(
                color_text(f"  Derivation Index: {entry.get('index', index)}", "index")
            )
            notes = entry.get("notes", "")
            if notes:
                print(color_text(f"  Notes: {notes}", "index"))
            tags = entry.get("tags", [])
            if tags:
                print(color_text(f"  Tags: {', '.join(tags)}", "index"))
        else:
            website = entry.get("label", entry.get("website", ""))
            username = entry.get("username", "")
            url = entry.get("url", "")
            blacklisted = entry.get("archived", entry.get("blacklisted", False))
            print(color_text(f"  Label: {website}", "index"))
            print(color_text(f"  Username: {username or 'N/A'}", "index"))
            print(color_text(f"  URL: {url or 'N/A'}", "index"))
            print(
                color_text(
                    f"  Archived: {'Yes' if blacklisted else 'No'}",
                    "index",
                )
            )
        print("-" * 40)

    def handle_list_entries(self) -> None:
        """List entries and optionally show details."""
        try:
            while True:
                fp, parent_fp, child_fp = self.header_fingerprint_args
                clear_and_print_fingerprint(
                    fp,
                    "Main Menu > List Entries",
                    parent_fingerprint=parent_fp,
                    child_fingerprint=child_fp,
                )
                print(color_text("\nList Entries:", "menu"))
                print(color_text("1. All", "menu"))
                print(color_text("2. Passwords", "menu"))
                print(color_text("3. 2FA (TOTP)", "menu"))
                print(color_text("4. SSH Key", "menu"))
                print(color_text("5. Seed Phrase", "menu"))
                print(color_text("6. Nostr Key Pair", "menu"))
                print(color_text("7. PGP", "menu"))
                print(color_text("8. Key/Value", "menu"))
                print(color_text("9. Managed Account", "menu"))
                choice = input("Select entry type or press Enter to go back: ").strip()
                if choice == "1":
                    filter_kind = None
                elif choice == "2":
                    filter_kind = EntryType.PASSWORD.value
                elif choice == "3":
                    filter_kind = EntryType.TOTP.value
                elif choice == "4":
                    filter_kind = EntryType.SSH.value
                elif choice == "5":
                    filter_kind = EntryType.SEED.value
                elif choice == "6":
                    filter_kind = EntryType.NOSTR.value
                elif choice == "7":
                    filter_kind = EntryType.PGP.value
                elif choice == "8":
                    filter_kind = EntryType.KEY_VALUE.value
                elif choice == "9":
                    filter_kind = EntryType.MANAGED_ACCOUNT.value
                elif not choice:
                    return
                else:
                    print(colored("Invalid choice.", "red"))
                    continue

                summaries = self.entry_manager.get_entry_summaries(
                    filter_kind, include_archived=False
                )
                if not summaries:
                    continue
                while True:
                    fp, parent_fp, child_fp = self.header_fingerprint_args
                    clear_and_print_fingerprint(
                        fp,
                        "Main Menu > List Entries",
                        parent_fingerprint=parent_fp,
                        child_fingerprint=child_fp,
                    )
                    print(colored("\n[+] Entries:\n", "green"))
                    for idx, etype, label in summaries:
                        if filter_kind is None:
                            display_type = etype.capitalize()
                            print(colored(f"{idx}. {display_type} - {label}", "cyan"))
                        else:
                            print(colored(f"{idx}. {label}", "cyan"))
                    idx_input = input(
                        "Enter index to view details or press Enter to go back: "
                    ).strip()
                    if not idx_input:
                        break
                    if not idx_input.isdigit():
                        print(colored("Invalid index.", "red"))
                        continue
                    self.show_entry_details_by_index(int(idx_input))
        except Exception as e:
            logging.error(f"Failed to list entries: {e}", exc_info=True)
            print(colored(f"Error: Failed to list entries: {e}", "red"))

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
                self.start_background_vault_sync()
                logging.info("Encrypted index posted to Nostr after entry deletion.")
            except Exception as nostr_error:
                logging.error(
                    f"Failed to post updated index to Nostr: {nostr_error}",
                    exc_info=True,
                )

        except Exception as e:
            logging.error(f"Error during entry deletion: {e}", exc_info=True)
            print(colored(f"Error: Failed to delete entry: {e}", "red"))

    def handle_archive_entry(self) -> None:
        """Archive an entry without deleting it."""
        try:
            index_input = input(
                "Enter the index number of the entry to archive: "
            ).strip()
            if not index_input.isdigit():
                print(colored("Error: Index must be a number.", "red"))
                return
            index = int(index_input)
            self.entry_manager.archive_entry(index)
            self.is_dirty = True
            self.last_update = time.time()
            pause()
        except Exception as e:
            logging.error(f"Error archiving entry: {e}", exc_info=True)
            print(colored(f"Error: Failed to archive entry: {e}", "red"))

    def handle_view_archived_entries(self) -> None:
        """Display archived entries and optionally view or restore them."""
        try:
            archived = self.entry_manager.list_entries(include_archived=True)
            archived = [e for e in archived if e[4]]
            if not archived:
                print(colored("No archived entries found.", "yellow"))
                pause()
                return
            while True:
                fp, parent_fp, child_fp = self.header_fingerprint_args
                clear_and_print_fingerprint(
                    fp,
                    "Main Menu > Archived Entries",
                    parent_fingerprint=parent_fp,
                    child_fingerprint=child_fp,
                )
                print(colored("\n[+] Archived Entries:\n", "green"))
                for idx, label, _username, _url, _ in archived:
                    print(colored(f"{idx}. {label}", "cyan"))
                idx_input = input(
                    "Enter index to manage or press Enter to go back: "
                ).strip()
                if not idx_input:
                    break
                if not idx_input.isdigit() or int(idx_input) not in [
                    e[0] for e in archived
                ]:
                    print(colored("Invalid index.", "red"))
                    continue
                entry_index = int(idx_input)
                while True:
                    action = (
                        input(
                            "Enter 'v' to view details, 'r' to restore, or press Enter to go back: "
                        )
                        .strip()
                        .lower()
                    )
                    if action == "v":
                        self.show_entry_details_by_index(entry_index)
                        pause()
                    elif action == "r":
                        self.entry_manager.restore_entry(entry_index)
                        self.is_dirty = True
                        self.last_update = time.time()
                        pause()
                        archived = self.entry_manager.list_entries(
                            include_archived=True
                        )
                        archived = [e for e in archived if e[4]]
                        if not archived:
                            print(colored("All entries restored.", "green"))
                            pause()
                            return
                        break
                    elif not action:
                        break
                    else:
                        print(colored("Invalid choice.", "red"))
        except Exception as e:
            logging.error(f"Error viewing archived entries: {e}", exc_info=True)
            print(colored(f"Error: Failed to view archived entries: {e}", "red"))

    def handle_display_totp_codes(self) -> None:
        """Display all stored TOTP codes with a countdown progress bar."""
        try:
            fp, parent_fp, child_fp = self.header_fingerprint_args
            clear_and_print_fingerprint(
                fp,
                "Main Menu > 2FA Codes",
                parent_fingerprint=parent_fp,
                child_fingerprint=child_fp,
            )
            data = self.entry_manager.vault.load_index()
            entries = data.get("entries", {})
            totp_list: list[tuple[str, int, int, bool]] = []
            for idx_str, entry in entries.items():
                if entry.get("type") == EntryType.TOTP.value and not entry.get(
                    "archived", entry.get("blacklisted", False)
                ):
                    label = entry.get("label", "")
                    period = int(entry.get("period", 30))
                    imported = "secret" in entry
                    totp_list.append((label, int(idx_str), period, imported))

            if not totp_list:
                print(colored("No 2FA entries found.", "yellow"))
                return

            totp_list.sort(key=lambda t: t[0].lower())
            print(colored("Press Enter to return to the menu.", "cyan"))
            while True:
                fp, parent_fp, child_fp = self.header_fingerprint_args
                clear_and_print_fingerprint(
                    fp,
                    "Main Menu > 2FA Codes",
                    parent_fingerprint=parent_fp,
                    child_fingerprint=child_fp,
                )
                print(colored("Press Enter to return to the menu.", "cyan"))
                generated = [t for t in totp_list if not t[3]]
                imported_list = [t for t in totp_list if t[3]]
                if generated:
                    print(colored("\nGenerated 2FA Codes:", "green"))
                    for label, idx, period, _ in generated:
                        code = self.entry_manager.get_totp_code(idx, self.parent_seed)
                        remaining = self.entry_manager.get_totp_time_remaining(idx)
                        filled = int(20 * (period - remaining) / period)
                        bar = "[" + "#" * filled + "-" * (20 - filled) + "]"
                        if self.secret_mode_enabled:
                            copy_to_clipboard(code, self.clipboard_clear_delay)
                            print(
                                f"[{idx}] {label}: [HIDDEN] {bar} {remaining:2d}s - copied to clipboard"
                            )
                        else:
                            print(
                                f"[{idx}] {label}: {color_text(code, 'deterministic')} {bar} {remaining:2d}s"
                            )
                if imported_list:
                    print(colored("\nImported 2FA Codes:", "green"))
                    for label, idx, period, _ in imported_list:
                        code = self.entry_manager.get_totp_code(idx, self.parent_seed)
                        remaining = self.entry_manager.get_totp_time_remaining(idx)
                        filled = int(20 * (period - remaining) / period)
                        bar = "[" + "#" * filled + "-" * (20 - filled) + "]"
                        if self.secret_mode_enabled:
                            copy_to_clipboard(code, self.clipboard_clear_delay)
                            print(
                                f"[{idx}] {label}: [HIDDEN] {bar} {remaining:2d}s - copied to clipboard"
                            )
                        else:
                            print(
                                f"[{idx}] {label}: {color_text(code, 'imported')} {bar} {remaining:2d}s"
                            )
                sys.stdout.flush()
                try:
                    user_input = timed_input("", 1)
                    if user_input.strip() == "" or user_input.strip().lower() == "b":
                        break
                except TimeoutError:
                    pass
                except KeyboardInterrupt:
                    print()
                    break
        except Exception as e:
            logging.error(f"Error displaying TOTP codes: {e}", exc_info=True)
            print(colored(f"Error: Failed to display TOTP codes: {e}", "red"))

    def handle_verify_checksum(self) -> None:
        """
        Handles verifying the script's checksum against the stored checksum to ensure integrity.
        """
        try:
            fp, parent_fp, child_fp = self.header_fingerprint_args
            clear_and_print_fingerprint(
                fp,
                "Main Menu > Settings > Verify Script Checksum",
                parent_fingerprint=parent_fp,
                child_fingerprint=child_fp,
            )
            current_checksum = calculate_checksum(__file__)
            try:
                verified = verify_checksum(current_checksum, SCRIPT_CHECKSUM_FILE)
            except FileNotFoundError:
                print(
                    colored(
                        "Checksum file missing. Run scripts/update_checksum.py or choose 'Generate Script Checksum' in Settings.",
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

    def handle_update_script_checksum(self) -> None:
        """Generate a new checksum for the manager script."""
        if not confirm_action("Generate new script checksum? (Y/N): "):
            print(colored("Operation cancelled.", "yellow"))
            return
        try:
            fp, parent_fp, child_fp = self.header_fingerprint_args
            clear_and_print_fingerprint(
                fp,
                "Main Menu > Settings > Generate Script Checksum",
                parent_fingerprint=parent_fp,
                child_fingerprint=child_fp,
            )
            script_path = Path(__file__).resolve()
            if update_checksum_file(str(script_path), str(SCRIPT_CHECKSUM_FILE)):
                print(
                    colored(
                        f"Checksum updated at '{SCRIPT_CHECKSUM_FILE}'.",
                        "green",
                    )
                )
            else:
                print(colored("Failed to update checksum.", "red"))
        except Exception as e:
            logging.error(f"Error updating checksum: {e}", exc_info=True)
            print(colored(f"Error: Failed to update checksum: {e}", "red"))

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
            if getattr(self, "offline_mode", False):
                return None
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
            fp, parent_fp, child_fp = self.header_fingerprint_args
            clear_and_print_fingerprint(
                fp,
                "Main Menu > Settings > Export database",
                parent_fingerprint=parent_fp,
                child_fingerprint=child_fp,
            )
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
            fp, parent_fp, child_fp = self.header_fingerprint_args
            clear_and_print_fingerprint(
                fp,
                "Main Menu > Settings > Import database",
                parent_fingerprint=parent_fp,
                child_fingerprint=child_fp,
            )
            import_backup(
                self.vault,
                self.backup_manager,
                src,
                parent_seed=self.parent_seed,
            )
            print(colored("Database imported successfully.", "green"))
            self.sync_vault()
        except Exception as e:
            logging.error(f"Failed to import database: {e}", exc_info=True)
            print(colored(f"Error: Failed to import database: {e}", "red"))

    def handle_export_totp_codes(self) -> Path | None:
        """Export all 2FA codes to a JSON file for other authenticator apps."""
        try:
            fp, parent_fp, child_fp = self.header_fingerprint_args
            clear_and_print_fingerprint(
                fp,
                "Main Menu > Settings > Export 2FA codes",
                parent_fingerprint=parent_fp,
                child_fingerprint=child_fp,
            )
            data = self.entry_manager.vault.load_index()
            entries = data.get("entries", {})

            totp_entries = []
            for entry in entries.values():
                if entry.get("type") == EntryType.TOTP.value:
                    label = entry.get("label", "")
                    period = int(entry.get("period", 30))
                    digits = int(entry.get("digits", 6))
                    if "secret" in entry:
                        secret = entry["secret"]
                    else:
                        idx = int(entry.get("index", 0))
                        secret = TotpManager.derive_secret(self.parent_seed, idx)
                    uri = TotpManager.make_otpauth_uri(label, secret, period, digits)
                    totp_entries.append(
                        {
                            "label": label,
                            "secret": secret,
                            "period": period,
                            "digits": digits,
                            "uri": uri,
                        }
                    )

            if not totp_entries:
                print(colored("No 2FA codes to export.", "yellow"))
                return None

            dest_str = input(
                "Enter destination file path (default: totp_export.json): "
            ).strip()
            dest = Path(dest_str) if dest_str else Path("totp_export.json")

            json_data = json.dumps({"entries": totp_entries}, indent=2)

            if confirm_action("Encrypt export with a password? (Y/N): "):
                password = prompt_new_password()
                iterations = self.config_manager.get_kdf_iterations()
                key = derive_key_from_password(password, iterations=iterations)
                enc_mgr = EncryptionManager(key, dest.parent)
                data_bytes = enc_mgr.encrypt_data(json_data.encode("utf-8"))
                dest = dest.with_suffix(dest.suffix + ".enc")
                dest.write_bytes(data_bytes)
            else:
                dest.write_text(json_data)

            os.chmod(dest, 0o600)
            print(colored(f"2FA codes exported to '{dest}'.", "green"))
            return dest
        except Exception as e:
            logging.error(f"Failed to export TOTP codes: {e}", exc_info=True)
            print(colored(f"Error: Failed to export 2FA codes: {e}", "red"))
            return None

    def handle_backup_reveal_parent_seed(self, file: Path | None = None) -> None:
        """Reveal the parent seed and optionally save an encrypted backup.

        Parameters
        ----------
        file:
            Optional path where an encrypted backup should be written. When
            provided, the confirmation and filename prompts are skipped and the
            seed is saved directly to this location.
        """
        try:
            fp, parent_fp, child_fp = self.header_fingerprint_args
            clear_and_print_fingerprint(
                fp,
                "Main Menu > Settings > Backup Parent Seed",
                parent_fingerprint=parent_fp,
                child_fingerprint=child_fp,
            )
            print(colored("\n=== Backup Parent Seed ===", "yellow"))
            print(
                colored(
                    "Warning: Revealing your parent seed is a highly sensitive operation.",
                    "yellow",
                )
            )
            print(
                colored(
                    "Ensure you're in a secure, private environment and no one is watching your screen.",
                    "yellow",
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
            print(color_text(self.parent_seed, "imported"))
            print(
                colored(
                    "\nPlease write this down and store it securely. Do not share it with anyone.",
                    "red",
                )
            )

            backup_path: Path | None = None
            if file is not None:
                backup_path = file
                save = True
            else:
                save = confirm_action(
                    "Do you want to save this to an encrypted backup file? (Y/N): "
                )
                if save:
                    filename = input(
                        f"Enter filename to save (default: {DEFAULT_SEED_BACKUP_FILENAME}): "
                    ).strip()
                    filename = filename if filename else DEFAULT_SEED_BACKUP_FILENAME
                    backup_path = self.fingerprint_dir / filename

            if save and backup_path is not None:
                if not self.is_valid_filename(backup_path.name):
                    print(colored("Invalid filename. Operation aborted.", "red"))
                    return

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

            iterations = self.config_manager.get_kdf_iterations()
            seed_key = derive_key_from_password(new_password, iterations=iterations)
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
                config_manager=self.config_manager,
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

    def get_profile_stats(self) -> dict:
        """Return various statistics about the current seed profile."""
        if not all([self.entry_manager, self.config_manager, self.backup_manager]):
            return {}

        stats: dict[str, object] = {}

        # Entry counts by type
        data = self.entry_manager.vault.load_index()
        entries = data.get("entries", {})
        counts: dict[str, int] = {etype.value: 0 for etype in EntryType}
        for entry in entries.values():
            etype = entry.get("type", EntryType.PASSWORD.value)
            counts[etype] = counts.get(etype, 0) + 1
        stats["entries"] = counts
        stats["total_entries"] = len(entries)

        # Schema version and database checksum status
        stats["schema_version"] = data.get("schema_version")
        json_content = json.dumps(data, indent=4)
        current_checksum = hashlib.sha256(json_content.encode("utf-8")).hexdigest()
        chk_path = self.entry_manager.checksum_file
        if chk_path.exists():
            stored = chk_path.read_text().strip()
            stats["checksum_ok"] = stored == current_checksum
        else:
            stored = None
            stats["checksum_ok"] = False
        stats["checksum"] = stored

        # Script checksum status
        script_path = Path(__file__).resolve()
        try:
            script_checksum = calculate_checksum(str(script_path))
        except Exception:
            script_checksum = None

        if SCRIPT_CHECKSUM_FILE.exists() and script_checksum:
            stored_script = SCRIPT_CHECKSUM_FILE.read_text().strip()
            stats["script_checksum_ok"] = stored_script == script_checksum
        else:
            stats["script_checksum_ok"] = False

        # Relay info
        cfg = self.config_manager.load_config(require_pin=False)
        relays = cfg.get("relays", [])
        stats["relays"] = relays
        stats["relay_count"] = len(relays)

        # Backup info
        backups = list(
            self.backup_manager.backup_dir.glob("entries_db_backup_*.json.enc")
        )
        stats["backup_count"] = len(backups)
        stats["backup_dir"] = str(self.backup_manager.backup_dir)
        stats["additional_backup_path"] = (
            self.config_manager.get_additional_backup_path()
        )

        # Nostr sync info
        manifest = getattr(self.nostr_client, "current_manifest", None)
        if manifest is not None:
            stats["chunk_count"] = len(manifest.chunks)
            stats["delta_since"] = manifest.delta_since
            stats["pending_deltas"] = len(
                getattr(self.nostr_client, "_delta_events", [])
            )
        else:
            stats["chunk_count"] = 0
            stats["delta_since"] = None
            stats["pending_deltas"] = 0

        return stats

    def display_stats(self) -> None:
        """Print a summary of :meth:`get_profile_stats` to the console."""
        stats = self.get_profile_stats()
        if not stats:
            print(colored("No statistics available.", "red"))
            return

        print(color_text("\n=== Seed Profile Stats ===", "stats"))
        print(color_text(f"Total entries: {stats['total_entries']}", "stats"))
        for etype, count in stats["entries"].items():
            print(color_text(f"  {etype}: {count}", "stats"))
        print(color_text(f"Relays configured: {stats['relay_count']}", "stats"))
        print(
            color_text(
                f"Backups: {stats['backup_count']} (dir: {stats['backup_dir']})",
                "stats",
            )
        )
        if stats.get("additional_backup_path"):
            print(
                color_text(
                    f"Additional backup: {stats['additional_backup_path']}", "stats"
                )
            )
        print(color_text(f"Schema version: {stats['schema_version']}", "stats"))
        print(
            color_text(
                f"Database checksum ok: {'yes' if stats['checksum_ok'] else 'no'}",
                "stats",
            )
        )
        print(
            color_text(
                f"Script checksum ok: {'yes' if stats['script_checksum_ok'] else 'no'}",
                "stats",
            )
        )
        print(color_text(f"Snapshot chunks: {stats['chunk_count']}", "stats"))
        print(color_text(f"Pending deltas: {stats['pending_deltas']}", "stats"))
        if stats.get("delta_since"):
            print(
                color_text(f"Latest delta timestamp: {stats['delta_since']}", "stats")
            )
