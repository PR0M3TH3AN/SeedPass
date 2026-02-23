# utils/password_prompt.py

"""
Password Prompt Module

This module provides functions to securely prompt users for passwords, ensuring that passwords
are entered and confirmed correctly. It handles both the creation of new passwords and the
input of existing passwords for decryption purposes. By centralizing password prompting logic,
this module enhances code reuse, security, and maintainability across the application.

Ensure that all dependencies are installed and properly configured in your environment.
"""

from utils.seed_prompt import masked_input
import logging
import os
import sys
import time
import unicodedata

from termcolor import colored
from colorama import init as colorama_init

from constants import MIN_PASSWORD_LENGTH

# Initialize colorama for colored terminal text
colorama_init()

# Instantiate the logger
logger = logging.getLogger(__name__)


DEFAULT_MAX_ATTEMPTS = 5


def _env_password() -> str | None:
    """Return a password supplied via environment for non-interactive use."""

    return os.getenv("SEEDPASS_TEST_PASSWORD") or os.getenv("SEEDPASS_PASSWORD")


def _get_max_attempts(override: int | None = None) -> int:
    """Return the configured maximum number of prompt attempts."""

    if override is not None:
        return override
    env = os.getenv("SEEDPASS_MAX_PROMPT_ATTEMPTS")
    if env is not None:
        try:
            return int(env)
        except ValueError:
            pass
    return DEFAULT_MAX_ATTEMPTS


def _apply_backoff(attempts: int, max_attempts: int) -> None:
    """Sleep using exponential backoff unless disabled."""

    if max_attempts == 0:
        return
    delay = 2 ** (attempts - 1)
    time.sleep(delay)


class PasswordPromptError(Exception):
    """Exception raised for password prompt errors."""

    pass


def prompt_new_password(max_retries: int | None = None) -> str:
    """
    Prompts the user to enter and confirm a new password for encrypting the parent seed.

    This function ensures that the password meets the minimum length requirement and that the
    password and confirmation match. It provides user-friendly messages and handles retries with
    an exponential backoff between attempts.

    Parameters:
        max_retries (int | None): Maximum number of attempts before aborting. ``0`` disables the
            limit. Defaults to the ``SEEDPASS_MAX_PROMPT_ATTEMPTS`` environment variable or ``5``.

    Returns:
        str: The confirmed password entered by the user.

    Raises:
        PasswordPromptError: If the user fails to provide a valid password after multiple attempts.
    """
    env_pw = _env_password()
    if env_pw:
        normalized = unicodedata.normalize("NFKD", env_pw)
        if len(normalized) < MIN_PASSWORD_LENGTH:
            raise PasswordPromptError("Environment password too short")
        return normalized

    max_retries = _get_max_attempts(max_retries)
    attempts = 0

    while max_retries == 0 or attempts < max_retries:
        try:
            password = masked_input("Enter a new password: ").strip()
            confirm_password = masked_input("Confirm your password: ").strip()

            if not password:
                print(
                    colored("Error: Password cannot be empty. Please try again.", "red")
                )
                logging.warning("User attempted to enter an empty password.")
                attempts += 1
                _apply_backoff(attempts, max_retries)
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
                _apply_backoff(attempts, max_retries)
                continue

            if password != confirm_password:
                print(
                    colored("Error: Passwords do not match. Please try again.", "red")
                )
                logging.warning("User entered mismatching passwords.")
                attempts += 1
                _apply_backoff(attempts, max_retries)
                continue

            # Normalize the password to NFKD form
            normalized_password = unicodedata.normalize("NFKD", password)
            logging.debug("User entered a valid and confirmed password.")
            return normalized_password

        except KeyboardInterrupt:
            print(colored("\nOperation cancelled by user.", "yellow"))
            logging.info("Password prompt interrupted by user.")
            raise PasswordPromptError("Operation cancelled by user")
        except Exception as e:
            logging.error(
                f"Unexpected error during password prompt: {e}", exc_info=True
            )
            print(colored(f"Error: {e}", "red"))
            attempts += 1
            _apply_backoff(attempts, max_retries)

    print(colored("Maximum password attempts exceeded. Exiting.", "red"))
    logging.error("User failed to provide a valid password after multiple attempts.")
    raise PasswordPromptError("Maximum password attempts exceeded")


def prompt_existing_password(
    prompt_message: str = "Enter your password: ", max_retries: int | None = None
) -> str:
    """
    Prompt the user for an existing password.

    The user will be reprompted on empty input up to ``max_retries`` times with
    an exponential backoff between attempts.

    Parameters:
        prompt_message (str): Message displayed when prompting for the password.
        max_retries (int | None): Number of attempts allowed before aborting. ``0``
            disables the limit. Defaults to the ``SEEDPASS_MAX_PROMPT_ATTEMPTS``
            environment variable or ``5``.

    Returns:
        str: The password provided by the user.

    Raises:
        PasswordPromptError: If the user interrupts the operation or exceeds
            ``max_retries`` attempts.
    """
    env_pw = _env_password()
    if env_pw:
        return unicodedata.normalize("NFKD", env_pw)

    max_retries = _get_max_attempts(max_retries)
    attempts = 0
    while max_retries == 0 or attempts < max_retries:
        try:
            password = masked_input(prompt_message).strip()

            if not password:
                print(
                    colored("Error: Password cannot be empty. Please try again.", "red")
                )
                logging.warning("User attempted to enter an empty password.")
                attempts += 1
                _apply_backoff(attempts, max_retries)
                continue

            normalized_password = unicodedata.normalize("NFKD", password)
            logging.debug("User entered an existing password for decryption.")
            return normalized_password

        except KeyboardInterrupt:
            print(colored("\nOperation cancelled by user.", "yellow"))
            logging.info("Existing password prompt interrupted by user.")
            raise PasswordPromptError("Operation cancelled by user")
        except Exception as e:
            logging.error(
                f"Unexpected error during existing password prompt: {e}",
                exc_info=True,
            )
            print(colored(f"Error: {e}", "red"))
            attempts += 1
            _apply_backoff(attempts, max_retries)

    raise PasswordPromptError("Maximum password attempts exceeded")


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
        PasswordPromptError: If the user interrupts the operation.
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
        raise PasswordPromptError("Operation cancelled by user")
    except Exception as e:
        logging.error(
            f"Unexpected error during action confirmation: {e}", exc_info=True
        )
        print(colored(f"Error: {e}", "red"))
        raise PasswordPromptError(str(e))


def prompt_for_password() -> str:
    """
    Prompts the user to enter a new password by invoking the prompt_new_password function.

    This function serves as an alias to maintain consistency with import statements in other modules.

    Returns:
        str: The confirmed password entered by the user.
    """
    return prompt_new_password()
