# utils/checksum.py

"""
Checksum Module

This module provides functionalities to calculate and verify SHA-256 checksums for files.
It ensures the integrity and authenticity of critical files within the application by
comparing computed checksums against stored values.

Ensure that all dependencies are installed and properly configured in your environment.
"""

import hashlib
import logging
import sys
import os
import json
from typing import Optional, Any

from termcolor import colored

from constants import APP_DIR, SCRIPT_CHECKSUM_FILE
from utils.atomic_write import atomic_write

# Instantiate the logger
logger = logging.getLogger(__name__)


def canonical_json_dumps(data: Any) -> str:
    """Serialize ``data`` into a canonical JSON string."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def json_checksum(data: Any) -> str:
    """Return SHA-256 checksum of canonical JSON serialization of ``data``."""
    canon = canonical_json_dumps(data)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


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
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        checksum = hasher.hexdigest()
        logging.debug(f"Calculated checksum for '{file_path}': {checksum}")
        return checksum
    except FileNotFoundError:
        logging.error(f"File '{file_path}' not found for checksum calculation.")
        print(
            colored(
                f"Error: File '{file_path}' not found for checksum calculation.", "red"
            )
        )
        return None
    except Exception as e:
        logging.error(
            f"Error calculating checksum for '{file_path}': {e}", exc_info=True
        )
        print(
            colored(
                f"Error: Failed to calculate checksum for '{file_path}': {e}", "red"
            )
        )
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
        with open(checksum_file_path, "r") as f:
            stored_checksum = f.read().strip()
    except FileNotFoundError:
        logging.error(f"Checksum file '{checksum_file_path}' not found.")
        raise
    except Exception as e:
        logging.error(
            f"Error reading checksum file '{checksum_file_path}': {e}", exc_info=True
        )
        raise

    if current_checksum == stored_checksum:
        logging.debug(f"Checksum verification passed for '{checksum_file_path}'.")
        return True
    else:
        logging.warning(f"Checksum mismatch for '{checksum_file_path}'.")
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
        hasher.update(content.encode("utf-8"))
        new_checksum = hasher.hexdigest()
        atomic_write(checksum_file_path, lambda f: f.write(new_checksum))
        logging.debug(f"Updated checksum for '{checksum_file_path}' to: {new_checksum}")
        return True
    except Exception as e:
        logging.error(
            f"Failed to update checksum for '{checksum_file_path}': {e}", exc_info=True
        )
        print(
            colored(
                f"Error: Failed to update checksum for '{checksum_file_path}': {e}",
                "red",
            )
        )
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
        print(colored(f"Checksum verification passed for '{file_path}'.", "green"))
        logging.info(f"Checksum verification passed for '{file_path}'.")
        return True
    else:
        print(colored(f"Checksum verification failed for '{file_path}'.", "red"))
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
        atomic_write(checksum_file_path, lambda f: f.write(checksum))
        logging.debug(
            f"Initialized checksum file '{checksum_file_path}' with checksum: {checksum}"
        )
        print(colored(f"Initialized checksum for '{file_path}'.", "green"))
        return True
    except Exception as e:
        logging.error(
            f"Failed to initialize checksum file '{checksum_file_path}': {e}",
            exc_info=True,
        )
        print(
            colored(
                f"Error: Failed to initialize checksum file '{checksum_file_path}': {e}",
                "red",
            )
        )
        return False


def update_checksum_file(file_path: str, checksum_file_path: str) -> bool:
    """Update ``checksum_file_path`` with the SHA-256 checksum of ``file_path``."""
    checksum = calculate_checksum(file_path)
    if checksum is None:
        return False
    try:
        atomic_write(checksum_file_path, lambda f: f.write(checksum))
        logging.debug(
            f"Updated checksum for '{file_path}' to '{checksum}' at '{checksum_file_path}'."
        )
        return True
    except Exception as exc:
        logging.error(
            f"Failed to update checksum file '{checksum_file_path}': {exc}",
            exc_info=True,
        )
        print(
            colored(
                f"Error: Failed to update checksum file '{checksum_file_path}': {exc}",
                "red",
            )
        )
        return False
