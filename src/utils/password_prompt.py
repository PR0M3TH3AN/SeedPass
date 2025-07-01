# utils/password_prompt.py

"""
Password Prompt Module

This module provides functions to securely prompt users for passwords, ensuring that passwords
are entered and confirmed correctly. It handles both the creation of new passwords and the
input of existing passwords for decryption purposes. By centralizing password prompting logic,
this module enhances code reuse, security, and maintainability across the application.

Ensure that all dependencies are installed and properly configured in your environment.
"""

import getpass
import logging
import sys
import unicodedata
import traceback

from termcolor import colored
from colorama import init as colorama_init

from constants import MIN_PASSWORD_LENGTH

# Initialize colorama for colored terminal text
colorama_init()

# Instantiate the logger
logger = logging.getLogger(__name__)


def prompt_new_password() -> str:
    """
    Prompts the user to enter and confirm a new password for encrypting the parent seed.

    This function ensures that the password meets the minimum length requirement and that the
    password and confirmation match. It provides user-friendly messages and handles retries.

    Returns:
        str: The confirmed password entered by the user.

    Raises:
        SystemExit: If the user fails to provide a valid password after multiple attempts.
    """
    max_retries = 5
    attempts = 0

    while attempts < max_retries:
        try:
            password = getpass.getpass(prompt="Enter a new password: ").strip()
            confirm_password = getpass.getpass(prompt="Confirm your password: ").strip()

            if not password:
                print(
                    colored("Error: Password cannot be empty. Please try again.", "red")
                )
                logging.warning("User attempted to enter an empty password.")
                attempts += 1
                continue

            if len(password) < MIN_PASSWORD_LENGTH:
                print(
                    colored(
                        f"Error: Password must be at least {MIN_PASSWORD_LENGTH} characters long.",
                        "red",
                    )
                )
                logging.warning(
                    f"User entered a password shorter than {MIN_PASSWORD_LENGTH} characters."
                )
                attempts += 1
                continue

            if password != confirm_password:
                print(
                    colored("Error: Passwords do not match. Please try again.", "red")
                )
                logging.warning("User entered mismatching passwords.")
                attempts += 1
                continue

            # Normalize the password to NFKD form
            normalized_password = unicodedata.normalize("NFKD", password)
            logging.debug("User entered a valid and confirmed password.")
            return normalized_password

        except KeyboardInterrupt:
            print(colored("\nOperation cancelled by user.", "yellow"))
            logging.info("Password prompt interrupted by user.")
            sys.exit(0)
        except Exception as e:
            logging.error(f"Unexpected error during password prompt: {e}")
            logging.error(traceback.format_exc())  # Log full traceback
            print(colored(f"Error: {e}", "red"))
            attempts += 1

    print(colored("Maximum password attempts exceeded. Exiting.", "red"))
    logging.error("User failed to provide a valid password after multiple attempts.")
    sys.exit(1)


def prompt_existing_password(prompt_message: str = "Enter your password: ") -> str:
    """
    Prompts the user to enter an existing password, typically used for decryption purposes.

    This function ensures that the password is entered securely without echoing it to the terminal.

    Parameters:
        prompt_message (str): The message displayed to prompt the user. Defaults to "Enter your password: ".

    Returns:
        str: The password entered by the user.

    Raises:
        SystemExit: If the user interrupts the operation.
    """
    try:
        password = getpass.getpass(prompt=prompt_message).strip()

        if not password:
            print(colored("Error: Password cannot be empty.", "red"))
            logging.warning("User attempted to enter an empty password.")
            sys.exit(1)

        # Normalize the password to NFKD form
        normalized_password = unicodedata.normalize("NFKD", password)
        logging.debug("User entered an existing password for decryption.")
        return normalized_password

    except KeyboardInterrupt:
        print(colored("\nOperation cancelled by user.", "yellow"))
        logging.info("Existing password prompt interrupted by user.")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Unexpected error during existing password prompt: {e}")
        logging.error(traceback.format_exc())  # Log full traceback
        print(colored(f"Error: {e}", "red"))
        sys.exit(1)


def confirm_action(
    prompt_message: str = "Are you sure you want to proceed? (Y/N): ",
) -> bool:
    """
    Prompts the user to confirm an action, typically used before performing critical operations.

    Parameters:
        prompt_message (str): The confirmation message displayed to the user. Defaults to
                              "Are you sure you want to proceed? (Y/N): ".

    Returns:
        bool: True if the user confirms the action, False otherwise.

    Raises:
        SystemExit: If the user interrupts the operation.
    """
    try:
        while True:
            response = input(colored(prompt_message, "cyan")).strip().lower()
            if response in ["y", "yes"]:
                logging.debug("User confirmed the action.")
                return True
            elif response in ["n", "no"]:
                logging.debug("User declined the action.")
                return False
            else:
                print(colored("Please respond with 'Y' or 'N'.", "yellow"))

    except KeyboardInterrupt:
        print(colored("\nOperation cancelled by user.", "yellow"))
        logging.info("Action confirmation interrupted by user.")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Unexpected error during action confirmation: {e}")
        logging.error(traceback.format_exc())  # Log full traceback
        print(colored(f"Error: {e}", "red"))
        sys.exit(1)


def prompt_for_password() -> str:
    """
    Prompts the user to enter a new password by invoking the prompt_new_password function.

    This function serves as an alias to maintain consistency with import statements in other modules.

    Returns:
        str: The confirmed password entered by the user.
    """
    return prompt_new_password()
