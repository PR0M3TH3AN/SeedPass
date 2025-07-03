# main.py
import os
from pathlib import Path
import sys
import logging
import signal
import getpass
import time
import argparse
import asyncio
import gzip
import tomli
from colorama import init as colorama_init
from termcolor import colored
import traceback

from password_manager.manager import PasswordManager
from nostr.client import NostrClient
from constants import INACTIVITY_TIMEOUT
from utils.password_prompt import PasswordPromptError
from local_bip85.bip85 import Bip85Error


colorama_init()


def load_global_config() -> dict:
    """Load configuration from ~/.seedpass/config.toml if present."""
    config_path = Path.home() / ".seedpass" / "config.toml"
    if not config_path.exists():
        return {}
    try:
        with open(config_path, "rb") as f:
            return tomli.load(f)
    except Exception as exc:
        logging.warning(f"Failed to read {config_path}: {exc}")
        return {}


def configure_logging():
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)  # Keep this as DEBUG to capture all logs

    # Remove all handlers associated with the root logger object
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # Ensure the 'logs' directory exists
    log_directory = Path("logs")
    if not log_directory.exists():
        log_directory.mkdir(parents=True, exist_ok=True)

    # Create handlers
    c_handler = logging.StreamHandler(sys.stdout)
    f_handler = logging.FileHandler(log_directory / "main.log")

    # Set levels: only errors and critical messages will be shown in the console
    c_handler.setLevel(logging.ERROR)
    f_handler.setLevel(logging.DEBUG)

    # Create formatters and add them to handlers
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s [%(filename)s:%(lineno)d]"
    )
    c_handler.setFormatter(formatter)
    f_handler.setFormatter(formatter)

    # Add handlers to the logger
    logger.addHandler(c_handler)
    logger.addHandler(f_handler)

    # Set logging level for third-party libraries to WARNING to suppress their debug logs
    logging.getLogger("monstr").setLevel(logging.WARNING)
    logging.getLogger("nostr").setLevel(logging.WARNING)


def confirm_action(prompt: str) -> bool:
    """
    Prompts the user for confirmation.

    :param prompt: The confirmation message to display.
    :return: True if user confirms, False otherwise.
    """
    while True:
        choice = input(colored(prompt, "yellow")).strip().lower()
        if choice in ["y", "yes"]:
            return True
        elif choice in ["n", "no"]:
            return False
        else:
            print(colored("Please enter 'Y' or 'N'.", "red"))


def handle_switch_fingerprint(password_manager: PasswordManager):
    """
    Handles switching the active fingerprint.

    :param password_manager: An instance of PasswordManager.
    """
    try:
        fingerprints = password_manager.fingerprint_manager.list_fingerprints()
        if not fingerprints:
            print(
                colored(
                    "No seed profiles available to switch. Please add a new seed profile first.",
                    "yellow",
                )
            )
            return

        print(colored("Available Seed Profiles:", "cyan"))
        for idx, fp in enumerate(fingerprints, start=1):
            print(colored(f"{idx}. {fp}", "cyan"))

        choice = input("Select a seed profile by number to switch: ").strip()
        if not choice.isdigit() or not (1 <= int(choice) <= len(fingerprints)):
            print(colored("Invalid selection.", "red"))
            return

        selected_fingerprint = fingerprints[int(choice) - 1]
        if password_manager.select_fingerprint(selected_fingerprint):
            print(colored(f"Switched to seed profile {selected_fingerprint}.", "green"))
        else:
            print(colored("Failed to switch seed profile.", "red"))
    except Exception as e:
        logging.error(f"Error during fingerprint switch: {e}", exc_info=True)
        print(colored(f"Error: Failed to switch seed profile: {e}", "red"))


def handle_add_new_fingerprint(password_manager: PasswordManager):
    """
    Handles adding a new seed profile.

    :param password_manager: An instance of PasswordManager.
    """
    try:
        password_manager.add_new_fingerprint()
    except Exception as e:
        logging.error(f"Error adding new seed profile: {e}", exc_info=True)
        print(colored(f"Error: Failed to add new seed profile: {e}", "red"))


def handle_remove_fingerprint(password_manager: PasswordManager):
    """
    Handles removing an existing seed profile.

    :param password_manager: An instance of PasswordManager.
    """
    try:
        fingerprints = password_manager.fingerprint_manager.list_fingerprints()
        if not fingerprints:
            print(colored("No seed profiles available to remove.", "yellow"))
            return

        print(colored("Available Seed Profiles:", "cyan"))
        for idx, fp in enumerate(fingerprints, start=1):
            print(colored(f"{idx}. {fp}", "cyan"))

        choice = input("Select a seed profile by number to remove: ").strip()
        if not choice.isdigit() or not (1 <= int(choice) <= len(fingerprints)):
            print(colored("Invalid selection.", "red"))
            return

        selected_fingerprint = fingerprints[int(choice) - 1]
        confirm = confirm_action(
            f"Are you sure you want to remove seed profile {selected_fingerprint}? This will delete all associated data. (Y/N): "
        )
        if confirm:
            if password_manager.fingerprint_manager.remove_fingerprint(
                selected_fingerprint
            ):
                print(
                    colored(
                        f"Seed profile {selected_fingerprint} removed successfully.",
                        "green",
                    )
                )
            else:
                print(colored("Failed to remove seed profile.", "red"))
        else:
            print(colored("Seed profile removal cancelled.", "yellow"))
    except Exception as e:
        logging.error(f"Error removing seed profile: {e}", exc_info=True)
        print(colored(f"Error: Failed to remove seed profile: {e}", "red"))


def handle_list_fingerprints(password_manager: PasswordManager):
    """
    Handles listing all available seed profiles.

    :param password_manager: An instance of PasswordManager.
    """
    try:
        fingerprints = password_manager.fingerprint_manager.list_fingerprints()
        if not fingerprints:
            print(colored("No seed profiles available.", "yellow"))
            return

        print(colored("Available Seed Profiles:", "cyan"))
        for fp in fingerprints:
            print(colored(f"- {fp}", "cyan"))
    except Exception as e:
        logging.error(f"Error listing seed profiles: {e}", exc_info=True)
        print(colored(f"Error: Failed to list seed profiles: {e}", "red"))


def handle_display_npub(password_manager: PasswordManager):
    """
    Handles displaying the Nostr public key (npub) to the user.
    """
    try:
        npub = password_manager.nostr_client.key_manager.get_npub()
        if npub:
            print(colored(f"\nYour Nostr Public Key (npub):\n{npub}\n", "cyan"))
            logging.info("Displayed npub to the user.")
        else:
            print(colored("Nostr public key not available.", "red"))
            logging.error("Nostr public key not available.")
    except Exception as e:
        logging.error(f"Failed to display npub: {e}", exc_info=True)
        print(colored(f"Error: Failed to display npub: {e}", "red"))


def handle_post_to_nostr(
    password_manager: PasswordManager, alt_summary: str | None = None
):
    """
    Handles the action of posting the encrypted password index to Nostr.
    """
    try:
        event_id = password_manager.sync_vault(alt_summary=alt_summary)
        if event_id:
            print(
                colored(
                    f"\N{WHITE HEAVY CHECK MARK} Sync complete. Event ID: {event_id}",
                    "green",
                )
            )
            logging.info("Encrypted index posted to Nostr successfully.")
        else:
            print(colored("\N{CROSS MARK} Sync failed…", "red"))
            logging.error("Failed to post encrypted index to Nostr.")
    except Exception as e:
        logging.error(f"Failed to post to Nostr: {e}", exc_info=True)
        print(colored(f"Error: Failed to post to Nostr: {e}", "red"))


def handle_retrieve_from_nostr(password_manager: PasswordManager):
    """
    Handles the action of retrieving the encrypted password index from Nostr.
    """
    try:
        result = asyncio.run(password_manager.nostr_client.fetch_latest_snapshot())
        if result:
            manifest, chunks = result
            encrypted = gzip.decompress(b"".join(chunks))
            if manifest.delta_since:
                try:
                    version = int(manifest.delta_since)
                    deltas = asyncio.run(
                        password_manager.nostr_client.fetch_deltas_since(version)
                    )
                    if deltas:
                        encrypted = deltas[-1]
                except ValueError:
                    pass
            password_manager.encryption_manager.decrypt_and_save_index_from_nostr(
                encrypted
            )
            print(colored("Encrypted index retrieved and saved successfully.", "green"))
            logging.info("Encrypted index retrieved and saved successfully from Nostr.")
        else:
            print(colored("Failed to retrieve data from Nostr.", "red"))
            logging.error("Failed to retrieve data from Nostr.")
    except Exception as e:
        logging.error(f"Failed to retrieve from Nostr: {e}", exc_info=True)
        print(colored(f"Error: Failed to retrieve from Nostr: {e}", "red"))


def handle_view_relays(cfg_mgr: "ConfigManager") -> None:
    """Display the currently configured Nostr relays."""
    try:
        cfg = cfg_mgr.load_config(require_pin=False)
        relays = cfg.get("relays", [])
        if not relays:
            print(colored("No relays configured.", "yellow"))
            return
        print(colored("\nCurrent Relays:", "cyan"))
        for idx, relay in enumerate(relays, start=1):
            print(colored(f"{idx}. {relay}", "cyan"))
    except Exception as e:
        logging.error(f"Error displaying relays: {e}")
        print(colored(f"Error: {e}", "red"))


def _reload_relays(password_manager: PasswordManager, relays: list) -> None:
    """Reload NostrClient with the updated relay list."""
    try:
        password_manager.nostr_client.close_client_pool()
    except Exception as exc:
        logging.warning(f"Failed to close client pool: {exc}")
    try:
        password_manager.nostr_client.relays = relays
        password_manager.nostr_client.initialize_client_pool()
    except Exception as exc:
        logging.error(f"Failed to reinitialize NostrClient: {exc}")


def handle_add_relay(password_manager: PasswordManager) -> None:
    """Prompt for a relay URL and add it to the config."""
    cfg_mgr = password_manager.config_manager
    if cfg_mgr is None:
        print(colored("Configuration manager unavailable.", "red"))
        return
    url = input("Enter relay URL to add: ").strip()
    if not url:
        print(colored("No URL entered.", "yellow"))
        return
    try:
        cfg = cfg_mgr.load_config(require_pin=False)
        relays = cfg.get("relays", [])
        if url in relays:
            print(colored("Relay already present.", "yellow"))
            return
        relays.append(url)
        cfg_mgr.set_relays(relays)
        _reload_relays(password_manager, relays)
        print(colored("Relay added.", "green"))
        try:
            handle_post_to_nostr(password_manager)
        except Exception as backup_error:
            logging.error(f"Failed to backup index to Nostr: {backup_error}")
    except Exception as e:
        logging.error(f"Error adding relay: {e}")
        print(colored(f"Error: {e}", "red"))


def handle_remove_relay(password_manager: PasswordManager) -> None:
    """Remove a relay from the config by its index."""
    cfg_mgr = password_manager.config_manager
    if cfg_mgr is None:
        print(colored("Configuration manager unavailable.", "red"))
        return
    try:
        cfg = cfg_mgr.load_config(require_pin=False)
        relays = cfg.get("relays", [])
        if not relays:
            print(colored("No relays configured.", "yellow"))
            return
        for idx, relay in enumerate(relays, start=1):
            print(colored(f"{idx}. {relay}", "cyan"))
        choice = input("Select relay number to remove: ").strip()
        if not choice.isdigit() or not (1 <= int(choice) <= len(relays)):
            print(colored("Invalid selection.", "red"))
            return
        if len(relays) == 1:
            print(
                colored(
                    "At least one relay must be configured. Add another before removing this one.",
                    "red",
                )
            )
            return
        relays.pop(int(choice) - 1)
        cfg_mgr.set_relays(relays)
        _reload_relays(password_manager, relays)
        print(colored("Relay removed.", "green"))
    except Exception as e:
        logging.error(f"Error removing relay: {e}")
        print(colored(f"Error: {e}", "red"))


def handle_reset_relays(password_manager: PasswordManager) -> None:
    """Reset relay list to defaults."""
    cfg_mgr = password_manager.config_manager
    if cfg_mgr is None:
        print(colored("Configuration manager unavailable.", "red"))
        return
    from nostr.client import DEFAULT_RELAYS

    try:
        cfg_mgr.set_relays(list(DEFAULT_RELAYS))
        _reload_relays(password_manager, list(DEFAULT_RELAYS))
        print(colored("Relays reset to defaults.", "green"))
    except Exception as e:
        logging.error(f"Error resetting relays: {e}")
        print(colored(f"Error: {e}", "red"))


def handle_set_inactivity_timeout(password_manager: PasswordManager) -> None:
    """Change the inactivity timeout for the current seed profile."""
    cfg_mgr = password_manager.config_manager
    if cfg_mgr is None:
        print(colored("Configuration manager unavailable.", "red"))
        return
    try:
        current = cfg_mgr.get_inactivity_timeout() / 60
        print(colored(f"Current timeout: {current:.1f} minutes", "cyan"))
    except Exception as e:
        logging.error(f"Error loading timeout: {e}")
        print(colored(f"Error: {e}", "red"))
        return
    value = input("Enter new timeout in minutes: ").strip()
    if not value:
        print(colored("No timeout entered.", "yellow"))
        return
    try:
        minutes = float(value)
        if minutes <= 0:
            print(colored("Timeout must be positive.", "red"))
            return
    except ValueError:
        print(colored("Invalid number.", "red"))
        return
    try:
        cfg_mgr.set_inactivity_timeout(minutes * 60)
        password_manager.inactivity_timeout = minutes * 60
        print(colored("Inactivity timeout updated.", "green"))
    except Exception as e:
        logging.error(f"Error saving timeout: {e}")
        print(colored(f"Error: {e}", "red"))


def handle_profiles_menu(password_manager: PasswordManager) -> None:
    """Submenu for managing seed profiles."""
    while True:
        print("\nProfiles:")
        print("1. Switch Seed Profile")
        print("2. Add a New Seed Profile")
        print("3. Remove an Existing Seed Profile")
        print("4. List All Seed Profiles")
        print("5. Back")
        choice = input("Select an option: ").strip()
        password_manager.update_activity()
        if choice == "1":
            if not password_manager.handle_switch_fingerprint():
                print(colored("Failed to switch seed profile.", "red"))
        elif choice == "2":
            handle_add_new_fingerprint(password_manager)
        elif choice == "3":
            handle_remove_fingerprint(password_manager)
        elif choice == "4":
            handle_list_fingerprints(password_manager)
        elif choice == "5":
            break
        else:
            print(colored("Invalid choice.", "red"))


def handle_nostr_menu(password_manager: PasswordManager) -> None:
    """Submenu for Nostr-related actions and relay configuration."""
    cfg_mgr = password_manager.config_manager
    if cfg_mgr is None:
        print(colored("Configuration manager unavailable.", "red"))
        return
    try:
        cfg_mgr.load_config()
    except Exception as e:
        print(colored(f"Error loading settings: {e}", "red"))
        return

    while True:
        print("\nNostr Settings:")
        print("1. Backup to Nostr")
        print("2. Restore from Nostr")
        print("3. View current relays")
        print("4. Add a relay URL")
        print("5. Remove a relay by number")
        print("6. Reset to default relays")
        print("7. Display Nostr Public Key")
        print("8. Back")
        choice = input("Select an option: ").strip()
        password_manager.update_activity()
        if choice == "1":
            handle_post_to_nostr(password_manager)
        elif choice == "2":
            handle_retrieve_from_nostr(password_manager)
        elif choice == "3":
            handle_view_relays(cfg_mgr)
        elif choice == "4":
            handle_add_relay(password_manager)
        elif choice == "5":
            handle_remove_relay(password_manager)
        elif choice == "6":
            handle_reset_relays(password_manager)
        elif choice == "7":
            handle_display_npub(password_manager)
        elif choice == "8":
            break
        else:
            print(colored("Invalid choice.", "red"))


def handle_settings(password_manager: PasswordManager) -> None:
    """Interactive settings menu with submenus for profiles and Nostr."""
    while True:
        print("\nSettings:")
        print("1. Profiles")
        print("2. Nostr")
        print("3. Change password")
        print("4. Verify Script Checksum")
        print("5. Backup Parent Seed")
        print("6. Export database")
        print("7. Import database")
        print("8. Set inactivity timeout")
        print("9. Lock Vault")
        print("10. Back")
        choice = input("Select an option: ").strip()
        if choice == "1":
            handle_profiles_menu(password_manager)
        elif choice == "2":
            handle_nostr_menu(password_manager)
        elif choice == "3":
            password_manager.change_password()
        elif choice == "4":
            password_manager.handle_verify_checksum()
        elif choice == "5":
            password_manager.handle_backup_reveal_parent_seed()
        elif choice == "6":
            password_manager.handle_export_database()
        elif choice == "7":
            path = input("Enter path to backup file: ").strip()
            if path:
                password_manager.handle_import_database(Path(path))
        elif choice == "8":
            handle_set_inactivity_timeout(password_manager)
        elif choice == "9":
            password_manager.lock_vault()
            print(colored("Vault locked. Please re-enter your password.", "yellow"))
            password_manager.unlock_vault()
        elif choice == "10":
            break
        else:
            print(colored("Invalid choice.", "red"))


def display_menu(
    password_manager: PasswordManager,
    sync_interval: float = 60.0,
    inactivity_timeout: float = INACTIVITY_TIMEOUT,
):
    """
    Displays the interactive menu and handles user input to perform various actions.
    """
    menu = """
    Select an option:
    1. Add Entry
    2. Retrieve Entry
    3. Modify an Existing Entry
    4. Settings
    5. Exit
    """
    while True:
        if time.time() - password_manager.last_activity > inactivity_timeout:
            print(colored("Session timed out. Vault locked.", "yellow"))
            password_manager.lock_vault()
            password_manager.unlock_vault()
            continue
        # Periodically push updates to Nostr
        if (
            password_manager.is_dirty
            and time.time() - password_manager.last_update >= sync_interval
        ):
            handle_post_to_nostr(password_manager)
            password_manager.is_dirty = False

        # Flush logging handlers
        for handler in logging.getLogger().handlers:
            handler.flush()
        print(colored(menu, "cyan"))
        choice = input("Enter your choice (1-5): ").strip()
        password_manager.update_activity()
        if not choice:
            print(
                colored(
                    "No input detected. Please enter a number between 1 and 5.",
                    "yellow",
                )
            )
            continue  # Re-display the menu without marking as invalid
        if choice == "1":
            while True:
                print("\nAdd Entry:")
                print("1. Password")
                print("2. Back")
                sub_choice = input("Select entry type: ").strip()
                password_manager.update_activity()
                if sub_choice == "1":
                    password_manager.handle_add_password()
                    break
                elif sub_choice == "2":
                    break
                else:
                    print(colored("Invalid choice.", "red"))
        elif choice == "2":
            password_manager.update_activity()
            password_manager.handle_retrieve_entry()
        elif choice == "3":
            password_manager.update_activity()
            password_manager.handle_modify_entry()
        elif choice == "4":
            password_manager.update_activity()
            handle_settings(password_manager)
        elif choice == "5":
            logging.info("Exiting the program.")
            print(colored("Exiting the program.", "green"))
            password_manager.nostr_client.close_client_pool()
            sys.exit(0)
        else:
            print(colored("Invalid choice. Please select a valid option.", "red"))


if __name__ == "__main__":
    # Configure logging with both file and console handlers
    configure_logging()
    logger = logging.getLogger(__name__)
    logger.info("Starting SeedPass Password Manager")

    # Load config from disk and parse command-line arguments
    cfg = load_global_config()
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command")

    exp = sub.add_parser("export")
    exp.add_argument("--file")

    imp = sub.add_parser("import")
    imp.add_argument("--file")

    args = parser.parse_args()

    # Initialize PasswordManager and proceed with application logic
    try:
        password_manager = PasswordManager()
        logger.info("PasswordManager initialized successfully.")
    except (PasswordPromptError, Bip85Error) as e:
        logger.error(f"Failed to initialize PasswordManager: {e}", exc_info=True)
        print(colored(f"Error: Failed to initialize PasswordManager: {e}", "red"))
        sys.exit(1)
    except Exception as e:
        logger.error(f"Failed to initialize PasswordManager: {e}", exc_info=True)
        print(colored(f"Error: Failed to initialize PasswordManager: {e}", "red"))
        sys.exit(1)

    if args.command == "export":
        password_manager.handle_export_database(Path(args.file))
        sys.exit(0)
    elif args.command == "import":
        password_manager.handle_import_database(Path(args.file))
        sys.exit(0)

    # Register signal handlers for graceful shutdown
    def signal_handler(sig, frame):
        """
        Handles termination signals to gracefully shutdown the NostrClient.
        """
        print(colored("\nReceived shutdown signal. Exiting gracefully...", "yellow"))
        logging.info(f"Received shutdown signal: {sig}. Initiating graceful shutdown.")
        try:
            password_manager.nostr_client.close_client_pool()  # Gracefully close the ClientPool
            logging.info("NostrClient closed successfully.")
        except Exception as e:
            logging.error(f"Error during shutdown: {e}")
            print(colored(f"Error during shutdown: {e}", "red"))
        sys.exit(0)

    # Register the signal handlers
    signal.signal(signal.SIGINT, signal_handler)  # Handle Ctrl+C
    signal.signal(signal.SIGTERM, signal_handler)  # Handle termination signals

    # Display the interactive menu to the user
    try:
        display_menu(
            password_manager, inactivity_timeout=password_manager.inactivity_timeout
        )
    except KeyboardInterrupt:
        logger.info("Program terminated by user via KeyboardInterrupt.")
        print(colored("\nProgram terminated by user.", "yellow"))
        try:
            password_manager.nostr_client.close_client_pool()  # Gracefully close the ClientPool
            logging.info("NostrClient closed successfully.")
        except Exception as e:
            logging.error(f"Error during shutdown: {e}")
            print(colored(f"Error during shutdown: {e}", "red"))
        sys.exit(0)
    except (PasswordPromptError, Bip85Error) as e:
        logger.error(f"A user-related error occurred: {e}", exc_info=True)
        print(colored(f"Error: {e}", "red"))
        try:
            password_manager.nostr_client.close_client_pool()
            logging.info("NostrClient closed successfully.")
        except Exception as close_error:
            logging.error(f"Error during shutdown: {close_error}")
            print(colored(f"Error during shutdown: {close_error}", "red"))
        sys.exit(1)
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)
        print(colored(f"Error: An unexpected error occurred: {e}", "red"))
        try:
            password_manager.nostr_client.close_client_pool()  # Attempt to close the ClientPool
            logging.info("NostrClient closed successfully.")
        except Exception as close_error:
            logging.error(f"Error during shutdown: {close_error}")
            print(colored(f"Error during shutdown: {close_error}", "red"))
        sys.exit(1)
