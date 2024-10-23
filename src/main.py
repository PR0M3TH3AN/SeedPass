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
    """
    Configures logging with both file and console handlers.
    Logs errors in the terminal and all messages in the log file.
    """
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    if not logger.handlers:
        # Create handlers
        c_handler = logging.StreamHandler(sys.stdout)
        f_handler = logging.FileHandler(os.path.join('logs', 'main.log'))

        # Set levels
        c_handler.setLevel(logging.ERROR)
        f_handler.setLevel(logging.DEBUG)

        # Create formatters
        formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s [%(filename)s:%(lineno)d]')
        c_handler.setFormatter(formatter)
        f_handler.setFormatter(formatter)

        # Add handlers
        logger.addHandler(c_handler)
        logger.addHandler(f_handler)

    return logger

def display_menu(password_manager: PasswordManager, nostr_client: NostrClient):
    """
    Displays the interactive menu and handles user input to perform various actions.

    :param password_manager: An instance of PasswordManager.
    :param nostr_client: An instance of NostrClient.
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
    9. Exit
    """
    while True:
        print(colored(menu, 'cyan'))
        choice = input('Enter your choice (1-9): ').strip()  # Updated to include option 9
        if choice == '1':
            password_manager.handle_generate_password()
        elif choice == '2':
            password_manager.handle_retrieve_password()
        elif choice == '3':
            password_manager.handle_modify_entry()
        elif choice == '4':
            password_manager.handle_verify_checksum()
        elif choice == '5':
            handle_post_to_nostr(password_manager, nostr_client)
        elif choice == '6':
            handle_retrieve_from_nostr(password_manager, nostr_client)
        elif choice == '7':
            handle_display_npub(nostr_client)
        elif choice == '8':
            password_manager.handle_backup_reveal_parent_seed()  # Corrected variable name
        elif choice == '9':
            logging.info("Exiting the program.")
            print(colored("Exiting the program.", 'green'))
            nostr_client.close_client_pool()  # Gracefully close the ClientPool
            sys.exit(0)
        else:
            print(colored("Invalid choice. Please select a valid option.", 'red'))

def handle_display_npub(nostr_client: NostrClient):
    """
    Handles displaying the Nostr public key (npub) to the user.

    :param nostr_client: An instance of NostrClient.
    """
    try:
        npub = nostr_client.key_manager.get_npub()
        if npub:
            print(colored(f"\nYour Nostr Public Key (npub):\n{npub}\n", 'cyan'))
            logging.info("Displayed npub to the user.")
        else:
            print(colored("Nostr public key not available.", 'red'))
            logging.error("Nostr public key not available.")
    except Exception as e:
        logging.error(f"Failed to display npub: {e}")
        print(f"Error: Failed to display npub: {e}", 'red')

def handle_post_to_nostr(password_manager: PasswordManager, nostr_client: NostrClient):
    """
    Handles the action of posting the encrypted password index to Nostr.

    :param password_manager: An instance of PasswordManager.
    :param nostr_client: An instance of NostrClient.
    """
    try:
        # Get the encrypted data from the index file
        encrypted_data = password_manager.get_encrypted_data()
        if encrypted_data:
            # Post to Nostr
            nostr_client.publish_json_to_nostr(encrypted_data)
            print(colored("Encrypted index posted to Nostr successfully.", 'green'))
            logging.info("Encrypted index posted to Nostr successfully.")
        else:
            print(colored("No data available to post.", 'yellow'))
            logging.warning("No data available to post to Nostr.")
    except Exception as e:
        logging.error(f"Failed to post to Nostr: {e}")
        logging.error(traceback.format_exc())
        print(f"Error: Failed to post to Nostr: {e}", 'red')

def handle_retrieve_from_nostr(password_manager: PasswordManager, nostr_client: NostrClient):
    """
    Handles the action of retrieving the encrypted password index from Nostr.

    :param password_manager: An instance of PasswordManager.
    :param nostr_client: An instance of NostrClient.
    """
    try:
        # Retrieve from Nostr
        encrypted_data = nostr_client.retrieve_json_from_nostr_sync()
        if encrypted_data:
            # Decrypt and save the index
            password_manager.decrypt_and_save_index_from_nostr(encrypted_data)
            print(colored("Encrypted index retrieved and saved successfully.", 'green'))
            logging.info("Encrypted index retrieved and saved successfully from Nostr.")
        else:
            print(colored("Failed to retrieve data from Nostr.", 'red'))
            logging.error("Failed to retrieve data from Nostr.")
    except Exception as e:
        logging.error(f"Failed to retrieve from Nostr: {e}")
        logging.error(traceback.format_exc())
        print(f"Error: Failed to retrieve from Nostr: {e}", 'red')

def cleanup(nostr_client: NostrClient):
    """
    Cleanup function to gracefully close the NostrClient's event loop.
    This function is registered to run upon program termination.
    """
    try:
        nostr_client.close_client_pool()
    except Exception as e:
        logging.error(f"Cleanup failed: {e}")
        print(f"Error during cleanup: {e}", 'red')

if __name__ == '__main__':
    """
    The main entry point of the application.
    """
    # Configure logging with both file and console handlers
    configure_logging()

    # Initialize PasswordManager
    try:
        password_manager = PasswordManager()
        logging.info("PasswordManager initialized successfully.")
    except Exception as e:
        logging.error(f"Failed to initialize PasswordManager: {e}")
        logging.error(traceback.format_exc())  # Log full traceback
        print(f"Error: Failed to initialize PasswordManager: {e}", 'red')
        sys.exit(1)

    # Initialize NostrClient with the parent seed from PasswordManager
    try:
        nostr_client = NostrClient(parent_seed=password_manager.parent_seed)
        logging.info("NostrClient initialized successfully.")
    except Exception as e:
        logging.error(f"Failed to initialize NostrClient: {e}")
        logging.error(traceback.format_exc())  # Log full traceback
        print(f"Error: Failed to initialize NostrClient: {e}", 'red')
        sys.exit(1)

    # Register signal handlers for graceful shutdown
    def signal_handler(sig, frame):
        """
        Handles termination signals to gracefully shutdown the NostrClient.
        """
        print(colored("\nReceived shutdown signal. Exiting gracefully...", 'yellow'))
        logging.info(f"Received shutdown signal: {sig}. Initiating graceful shutdown.")
        try:
            nostr_client.close_client_pool()  # Gracefully close the ClientPool
            logging.info("NostrClient closed successfully.")
        except Exception as e:
            logging.error(f"Error during shutdown: {e}")
            print(f"Error during shutdown: {e}", 'red')
        sys.exit(0)

    # Register the signal handlers
    signal.signal(signal.SIGINT, signal_handler)   # Handle Ctrl+C
    signal.signal(signal.SIGTERM, signal_handler)  # Handle termination signals

    # Display the interactive menu to the user
    try:
        display_menu(password_manager, nostr_client)
    except KeyboardInterrupt:
        logging.info("Program terminated by user via KeyboardInterrupt.")
        print(colored("\nProgram terminated by user.", 'yellow'))
        try:
            nostr_client.close_client_pool()  # Gracefully close the ClientPool
            logging.info("NostrClient closed successfully.")
        except Exception as e:
            logging.error(f"Error during shutdown: {e}")
            print(f"Error during shutdown: {e}", 'red')
        sys.exit(0)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        logging.error(traceback.format_exc())  # Log full traceback
        print(f"Error: An unexpected error occurred: {e}", 'red')
        try:
            nostr_client.close_client_pool()  # Attempt to close the ClientPool
            logging.info("NostrClient closed successfully.")
        except Exception as close_error:
            logging.error(f"Error during shutdown: {close_error}")
            print(f"Error during shutdown: {close_error}", 'red')
        sys.exit(1)
