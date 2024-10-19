# utils/checksum.py

"""
Checksum Module

This module provides functionalities to calculate and verify SHA-256 checksums for files.
It ensures the integrity and authenticity of critical files within the application by
comparing computed checksums against stored values.

Dependencies:
- hashlib
- logging
- colored (from termcolor)
- constants.py
- sys

Ensure that all dependencies are installed and properly configured in your environment.
"""

import hashlib
import logging
import sys
import os
import traceback
from typing import Optional

from termcolor import colored

from constants import (
    APP_DIR,
    DATA_CHECKSUM_FILE,
    SCRIPT_CHECKSUM_FILE
)

# Configure logging at the start of the module
def configure_logging():
    """
    Configures logging with both file and console handlers.
    Only ERROR and higher-level messages are shown in the terminal, while all messages
    are logged in the log file.
    """
    # Create the 'logs' folder if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')

    # Create a custom logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)  # Set to DEBUG for detailed output

    # Create handlers
    c_handler = logging.StreamHandler()
    f_handler = logging.FileHandler(os.path.join('logs', 'checksum.log'))  # Log files will be in 'logs' folder

    # Set levels: only errors and critical messages will be shown in the console
    c_handler.setLevel(logging.ERROR)  # Terminal will show ERROR and above
    f_handler.setLevel(logging.DEBUG)  # File will log everything from DEBUG and above

    # Create formatters and add them to handlers, include file and line number in log messages
    c_format = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s [%(filename)s:%(lineno)d]')
    f_format = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s [%(filename)s:%(lineno)d]')

    c_handler.setFormatter(c_format)
    f_handler.setFormatter(f_format)

    # Add handlers to the logger
    logger.addHandler(c_handler)
    logger.addHandler(f_handler)

# Call the logging configuration function
configure_logging()

def calculate_checksum(file_path: str) -> Optional[str]:
    """
    Calculates the SHA-256 checksum of the given file.

    Parameters:
        file_path (str): Path to the file.

    Returns:
        Optional[str]: Hexadecimal SHA-256 checksum if successful, None otherwise.
    """
    hasher = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        checksum = hasher.hexdigest()
        logging.debug(f"Calculated checksum for '{file_path}': {checksum}")
        return checksum
    except FileNotFoundError:
        logging.error(f"File '{file_path}' not found for checksum calculation.")
        print(colored(f"Error: File '{file_path}' not found for checksum calculation.", 'red'))
        return None
    except Exception as e:
        logging.error(f"Error calculating checksum for '{file_path}': {e}")
        logging.error(traceback.format_exc())  # Log full traceback
        print(colored(f"Error: Failed to calculate checksum for '{file_path}': {e}", 'red'))
        return None


def verify_checksum(current_checksum: str, checksum_file_path: str) -> bool:
    """
    Verifies the current checksum against the stored checksum.

    Parameters:
        current_checksum (str): The newly calculated checksum.
        checksum_file_path (str): The checksum file to verify against.

    Returns:
        bool: True if checksums match, False otherwise.
    """
    try:
        with open(checksum_file_path, 'r') as f:
            stored_checksum = f.read().strip()
        if current_checksum == stored_checksum:
            logging.debug(f"Checksum verification passed for '{checksum_file_path}'.")
            return True
        else:
            logging.warning(f"Checksum mismatch for '{checksum_file_path}'.")
            return False
    except FileNotFoundError:
        logging.error(f"Checksum file '{checksum_file_path}' not found.")
        print(colored(f"Error: Checksum file '{checksum_file_path}' not found.", 'red'))
        return False
    except Exception as e:
        logging.error(f"Error reading checksum file '{checksum_file_path}': {e}")
        logging.error(traceback.format_exc())  # Log full traceback
        print(colored(f"Error: Failed to read checksum file '{checksum_file_path}': {e}", 'red'))
        return False


def update_checksum(content: str, checksum_file_path: str) -> bool:
    """
    Updates the stored checksum file with the provided content's checksum.

    Parameters:
        content (str): The content to calculate the checksum for.
        checksum_file_path (str): The path to the checksum file to update.

    Returns:
        bool: True if the checksum was successfully updated, False otherwise.
    """
    try:
        hasher = hashlib.sha256()
        hasher.update(content.encode('utf-8'))
        new_checksum = hasher.hexdigest()
        with open(checksum_file_path, 'w') as f:
            f.write(new_checksum)
        logging.debug(f"Updated checksum for '{checksum_file_path}' to: {new_checksum}")
        return True
    except Exception as e:
        logging.error(f"Failed to update checksum for '{checksum_file_path}': {e}")
        logging.error(traceback.format_exc())  # Log full traceback
        print(colored(f"Error: Failed to update checksum for '{checksum_file_path}': {e}", 'red'))
        return False


def verify_and_update_checksum(file_path: str, checksum_file_path: str) -> bool:
    """
    Verifies the checksum of a file against its stored checksum and updates it if necessary.

    Parameters:
        file_path (str): Path to the file to verify.
        checksum_file_path (str): Path to the checksum file.

    Returns:
        bool: True if verification is successful, False otherwise.
    """
    current_checksum = calculate_checksum(file_path)
    if current_checksum is None:
        return False

    if verify_checksum(current_checksum, checksum_file_path):
        print(colored(f"Checksum verification passed for '{file_path}'.", 'green'))
        logging.info(f"Checksum verification passed for '{file_path}'.")
        return True
    else:
        print(colored(f"Checksum verification failed for '{file_path}'.", 'red'))
        logging.warning(f"Checksum verification failed for '{file_path}'.")
        return False


def initialize_checksum(file_path: str, checksum_file_path: str) -> bool:
    """
    Initializes the checksum file by calculating the checksum of the given file.

    Parameters:
        file_path (str): Path to the file to calculate checksum for.
        checksum_file_path (str): Path to the checksum file to create.

    Returns:
        bool: True if initialization is successful, False otherwise.
    """
    checksum = calculate_checksum(file_path)
    if checksum is None:
        return False

    try:
        with open(checksum_file_path, 'w') as f:
            f.write(checksum)
        logging.debug(f"Initialized checksum file '{checksum_file_path}' with checksum: {checksum}")
        print(colored(f"Initialized checksum for '{file_path}'.", 'green'))
        return True
    except Exception as e:
        logging.error(f"Failed to initialize checksum file '{checksum_file_path}': {e}")
        logging.error(traceback.format_exc())  # Log full traceback
        print(colored(f"Error: Failed to initialize checksum file '{checksum_file_path}': {e}", 'red'))
        return False
