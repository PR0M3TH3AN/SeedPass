# main.py
import os
import sys
import logging
import signal
from colorama import init as colorama_init
from termcolor import colored
import traceback

from password_manager.manager import PasswordManager
from nostr.client import NostrClient

colorama_init()

def configure_logging():
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)  # Keep this as DEBUG to capture all logs

    # Remove all handlers associated with the root logger object
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # Ensure the 'logs' directory exists
    log_directory = 'logs'
    if not os.path.exists(log_directory):
        os.makedirs(log_directory)

    # Create handlers
    c_handler = logging.StreamHandler(sys.stdout)
    f_handler = logging.FileHandler(os.path.join(log_directory, 'main.log'))

    # Set levels: only errors and critical messages will be shown in the console
    c_handler.setLevel(logging.ERROR)
    f_handler.setLevel(logging.DEBUG)

    # Create formatters and add them to handlers
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s [%(filename)s:%(lineno)d]')
    c_handler.setFormatter(formatter)
    f_handler.setFormatter(formatter)

    # Add handlers to the logger
    logger.addHandler(c_handler)
    logger.addHandler(f_handler)

    # Set logging level for third-party libraries to WARNING to suppress their debug logs
    logging.getLogger('monstr').setLevel(logging.WARNING)
    logging.getLogger('nostr').setLevel(logging.WARNING)

def confirm_action(prompt: str) -> bool:
    """
    Prompts the user for confirmation.

    :param prompt: The confirmation message to display.
    :return: True if user confirms, False otherwise.
    """
    while True:
        choice = input(colored(prompt, 'yellow')).strip().lower()
        if choice in ['y', 'yes']:
            return True
        elif choice in ['n', 'no']:
            return False
        else:
            print(colored("Please enter 'Y' or 'N'.", 'red'))

def handle_switch_fingerprint(password_manager: PasswordManager):
    """
    Handles switching the active fingerprint.

    :param password_manager: An instance of PasswordManager.
    """
    try:
        fingerprints = password_manager.fingerprint_manager.list_fingerprints()
        if not fingerprints:
            print(colored("No fingerprints available to switch. Please add a new fingerprint first.", 'yellow'))
            return

        print(colored("Available Fingerprints:", 'cyan'))
        for idx, fp in enumerate(fingerprints, start=1):
            print(colored(f"{idx}. {fp}", 'cyan'))

        choice = input("Select a fingerprint by number to switch: ").strip()
        if not choice.isdigit() or not (1 <= int(choice) <= len(fingerprints)):
            print(colored("Invalid selection.", 'red'))
            return

        selected_fingerprint = fingerprints[int(choice)-1]
        if password_manager.select_fingerprint(selected_fingerprint):
            print(colored(f"Switched to fingerprint {selected_fingerprint}.", 'green'))
        else:
            print(colored("Failed to switch fingerprint.", 'red'))
    except Exception as e:
        logging.error(f"Error during fingerprint switch: {e}")
        logging.error(traceback.format_exc())
        print(colored(f"Error: Failed to switch fingerprint: {e}", 'red'))

def handle_add_new_fingerprint(password_manager: PasswordManager):
    """
    Handles adding a new fingerprint.

    :param password_manager: An instance of PasswordManager.
    """
    try:
        password_manager.add_new_fingerprint()
    except Exception as e:
        logging.error(f"Error adding new fingerprint: {e}")
        logging.error(traceback.format_exc())
        print(colored(f"Error: Failed to add new fingerprint: {e}", 'red'))

def handle_remove_fingerprint(password_manager: PasswordManager):
    """
    Handles removing an existing fingerprint.

    :param password_manager: An instance of PasswordManager.
    """
    try:
        fingerprints = password_manager.fingerprint_manager.list_fingerprints()
        if not fingerprints:
            print(colored("No fingerprints available to remove.", 'yellow'))
            return

        print(colored("Available Fingerprints:", 'cyan'))
        for idx, fp in enumerate(fingerprints, start=1):
            print(colored(f"{idx}. {fp}", 'cyan'))

        choice = input("Select a fingerprint by number to remove: ").strip()
        if not choice.isdigit() or not (1 <= int(choice) <= len(fingerprints)):
            print(colored("Invalid selection.", 'red'))
            return

        selected_fingerprint = fingerprints[int(choice)-1]
        confirm = confirm_action(f"Are you sure you want to remove fingerprint {selected_fingerprint}? This will delete all associated data. (Y/N): ")
        if confirm:
            if password_manager.fingerprint_manager.remove_fingerprint(selected_fingerprint):
                print(colored(f"Fingerprint {selected_fingerprint} removed successfully.", 'green'))
            else:
                print(colored("Failed to remove fingerprint.", 'red'))
        else:
            print(colored("Fingerprint removal cancelled.", 'yellow'))
    except Exception as e:
        logging.error(f"Error removing fingerprint: {e}")
        logging.error(traceback.format_exc())
        print(colored(f"Error: Failed to remove fingerprint: {e}", 'red'))

def handle_list_fingerprints(password_manager: PasswordManager):
    """
    Handles listing all available fingerprints.

    :param password_manager: An instance of PasswordManager.
    """
    try:
        fingerprints = password_manager.fingerprint_manager.list_fingerprints()
        if not fingerprints:
            print(colored("No fingerprints available.", 'yellow'))
            return

        print(colored("Available Fingerprints:", 'cyan'))
        for fp in fingerprints:
            print(colored(f"- {fp}", 'cyan'))
    except Exception as e:
        logging.error(f"Error listing fingerprints: {e}")
        logging.error(traceback.format_exc())
        print(colored(f"Error: Failed to list fingerprints: {e}", 'red'))

def handle_display_npub(password_manager: PasswordManager):
    """
    Handles displaying the Nostr public key (npub) to the user.
    """
    try:
        npub = password_manager.nostr_client.key_manager.get_npub()
        if npub:
            print(colored(f"\nYour Nostr Public Key (npub):\n{npub}\n", 'cyan'))
            logging.info("Displayed npub to the user.")
        else:
            print(colored("Nostr public key not available.", 'red'))
            logging.error("Nostr public key not available.")
    except Exception as e:
        logging.error(f"Failed to display npub: {e}")
        logging.error(traceback.format_exc())
        print(colored(f"Error: Failed to display npub: {e}", 'red'))

def handle_post_to_nostr(password_manager: PasswordManager):
    """
    Handles the action of posting the encrypted password index to Nostr.
    """
    try:
        # Get the encrypted data from the index file
        encrypted_data = password_manager.get_encrypted_data()
        if encrypted_data:
            # Post to Nostr
            password_manager.nostr_client.publish_json_to_nostr(encrypted_data)
            print(colored("Encrypted index posted to Nostr successfully.", 'green'))
            logging.info("Encrypted index posted to Nostr successfully.")
        else:
            print(colored("No data available to post.", 'yellow'))
            logging.warning("No data available to post to Nostr.")
    except Exception as e:
        logging.error(f"Failed to post to Nostr: {e}")
        logging.error(traceback.format_exc())
        print(colored(f"Error: Failed to post to Nostr: {e}", 'red'))

def handle_retrieve_from_nostr(password_manager: PasswordManager):
    """
    Handles the action of retrieving the encrypted password index from Nostr.
    """
    try:
        # Use the Nostr client from the password_manager
        encrypted_data = password_manager.nostr_client.retrieve_json_from_nostr_sync()
        if encrypted_data:
            # Decrypt and save the index
            password_manager.encryption_manager.decrypt_and_save_index_from_nostr(encrypted_data)
            print(colored("Encrypted index retrieved and saved successfully.", 'green'))
            logging.info("Encrypted index retrieved and saved successfully from Nostr.")
        else:
            print(colored("Failed to retrieve data from Nostr.", 'red'))
            logging.error("Failed to retrieve data from Nostr.")
    except Exception as e:
        logging.error(f"Failed to retrieve from Nostr: {e}")
        logging.error(traceback.format_exc())
        print(colored(f"Error: Failed to retrieve from Nostr: {e}", 'red'))

def display_menu(password_manager: PasswordManager):
    """
    Displays the interactive menu and handles user input to perform various actions.
    """
    menu = """
    Select an option:
    1. Generate a New Password and Add to Index
    2. Retrieve a Password from Index
    3. Modify an Existing Entry
    4. Verify Script Checksum
    5. Post Encrypted Index to Nostr
    6. Retrieve Encrypted Index from Nostr
    7. Display Nostr Public Key (npub)
    8. Backup/Reveal Parent Seed
    9. Switch Fingerprint
    10. Add a New Fingerprint
    11. Remove an Existing Fingerprint
    12. List All Fingerprints
    13. Exit
    """
    while True:
        # Flush logging handlers
        for handler in logging.getLogger().handlers:
            handler.flush()
        print(colored(menu, 'cyan'))
        choice = input('Enter your choice (1-13): ').strip()
        if not choice:
            print(colored("No input detected. Please enter a number between 1 and 13.", 'yellow'))
            continue  # Re-display the menu without marking as invalid
        if choice == '1':
            password_manager.handle_generate_password()
        elif choice == '2':
            password_manager.handle_retrieve_password()
        elif choice == '3':
            password_manager.handle_modify_entry()
        elif choice == '4':
            password_manager.handle_verify_checksum()
        elif choice == '5':
            handle_post_to_nostr(password_manager)
        elif choice == '6':
            handle_retrieve_from_nostr(password_manager)
        elif choice == '7':
            handle_display_npub(password_manager)
        elif choice == '8':
            password_manager.handle_backup_reveal_parent_seed()
        elif choice == '9':
            if not password_manager.handle_switch_fingerprint():
                print(colored("Failed to switch fingerprint.", 'red'))
        elif choice == '10':
            handle_add_new_fingerprint(password_manager)
        elif choice == '11':
            handle_remove_fingerprint(password_manager)
        elif choice == '12':
            handle_list_fingerprints(password_manager)
        elif choice == '13':
            logging.info("Exiting the program.")
            print(colored("Exiting the program.", 'green'))
            password_manager.nostr_client.close_client_pool()
            sys.exit(0)
        else:
            print(colored("Invalid choice. Please select a valid option.", 'red'))

if __name__ == '__main__':
    # Configure logging with both file and console handlers
    configure_logging()
    logger = logging.getLogger(__name__)
    logger.info("Starting SeedPass Password Manager")
    
    # Initialize PasswordManager and proceed with application logic
    try:
        password_manager = PasswordManager()
        logger.info("PasswordManager initialized successfully.")
    except Exception as e:
        logger.error(f"Failed to initialize PasswordManager: {e}")
        logger.error(traceback.format_exc())  # Log full traceback
        print(colored(f"Error: Failed to initialize PasswordManager: {e}", 'red'))
        sys.exit(1)
    
    # Register signal handlers for graceful shutdown
    def signal_handler(sig, frame):
        """
        Handles termination signals to gracefully shutdown the NostrClient.
        """
        print(colored("\nReceived shutdown signal. Exiting gracefully...", 'yellow'))
        logging.info(f"Received shutdown signal: {sig}. Initiating graceful shutdown.")
        try:
            password_manager.nostr_client.close_client_pool()  # Gracefully close the ClientPool
            logging.info("NostrClient closed successfully.")
        except Exception as e:
            logging.error(f"Error during shutdown: {e}")
            print(colored(f"Error during shutdown: {e}", 'red'))
        sys.exit(0)

    # Register the signal handlers
    signal.signal(signal.SIGINT, signal_handler)   # Handle Ctrl+C
    signal.signal(signal.SIGTERM, signal_handler)  # Handle termination signals
    
    # Display the interactive menu to the user
    try:
        display_menu(password_manager)
    except KeyboardInterrupt:
        logger.info("Program terminated by user via KeyboardInterrupt.")
        print(colored("\nProgram terminated by user.", 'yellow'))
        try:
            password_manager.nostr_client.close_client_pool()  # Gracefully close the ClientPool
            logging.info("NostrClient closed successfully.")
        except Exception as e:
            logging.error(f"Error during shutdown: {e}")
            print(colored(f"Error during shutdown: {e}", 'red'))
        sys.exit(0)
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        logger.error(traceback.format_exc())  # Log full traceback
        print(colored(f"Error: An unexpected error occurred: {e}", 'red'))
        try:
            password_manager.nostr_client.close_client_pool()  # Attempt to close the ClientPool
            logging.info("NostrClient closed successfully.")
        except Exception as close_error:
            logging.error(f"Error during shutdown: {close_error}")
            print(colored(f"Error during shutdown: {close_error}", 'red'))
        sys.exit(1)