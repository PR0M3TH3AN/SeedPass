# utils/file_lock.py

"""
File Lock Module

This module provides a single context manager, `lock_file`, for acquiring and releasing
locks on files using the `fcntl` library. It ensures that critical files are accessed
safely, preventing race conditions and maintaining data integrity when multiple processes
or threads attempt to read from or write to the same file concurrently.

I need to change this to something that supports Windows in the future.

Ensure that all dependencies are installed and properly configured in your environment.
"""

import os
import fcntl
import logging
from contextlib import contextmanager
from typing import Generator
from pathlib import Path
from termcolor import colored
import sys
import traceback

# Instantiate the logger
logger = logging.getLogger(__name__)


@contextmanager
def lock_file(file_path: Path, lock_type: int) -> Generator[None, None, None]:
    """
    Context manager to acquire a lock on a file.

    Parameters:
        file_path (Path): The path to the file to lock.
        lock_type (int): The type of lock to acquire (`fcntl.LOCK_EX` for exclusive,
                         `fcntl.LOCK_SH` for shared).

    Yields:
        None

    Raises:
        ValueError: If an invalid lock type is provided.
        SystemExit: Exits the program if the lock cannot be acquired.
    """
    if lock_type not in (fcntl.LOCK_EX, fcntl.LOCK_SH):
        logging.error(
            f"Invalid lock type: {lock_type}. Use fcntl.LOCK_EX or fcntl.LOCK_SH."
        )
        print(colored("Error: Invalid lock type provided.", "red"))
        sys.exit(1)

    file = None
    try:
        # Determine the mode based on whether the file exists
        mode = "rb+" if file_path.exists() else "wb"

        # Open the file
        file = open(file_path, mode)
        logging.debug(f"Opened file '{file_path}' in mode '{mode}' for locking.")

        # Acquire the lock
        fcntl.flock(file, lock_type)
        lock_type_str = "Exclusive" if lock_type == fcntl.LOCK_EX else "Shared"
        logging.debug(f"{lock_type_str} lock acquired on '{file_path}'.")
        yield  # Control is transferred to the block inside the `with` statement

    except IOError as e:
        lock_type_str = "exclusive" if lock_type == fcntl.LOCK_EX else "shared"
        logging.error(f"Failed to acquire {lock_type_str} lock on '{file_path}': {e}")
        logging.error(traceback.format_exc())  # Log full traceback
        print(
            colored(
                f"Error: Failed to acquire {lock_type_str} lock on '{file_path}': {e}",
                "red",
            )
        )
        sys.exit(1)

    finally:
        if file:
            try:
                # Release the lock
                fcntl.flock(file, fcntl.LOCK_UN)
                logging.debug(f"Lock released on '{file_path}'.")
            except Exception as e:
                lock_type_str = "exclusive" if lock_type == fcntl.LOCK_EX else "shared"
                logging.warning(
                    f"Failed to release {lock_type_str} lock on '{file_path}': {e}"
                )
                logging.error(traceback.format_exc())  # Log full traceback
                print(
                    colored(
                        f"Warning: Failed to release {lock_type_str} lock on '{file_path}': {e}",
                        "yellow",
                    )
                )
            finally:
                # Close the file
                try:
                    file.close()
                    logging.debug(f"File '{file_path}' closed successfully.")
                except Exception as e:
                    logging.warning(f"Failed to close file '{file_path}': {e}")
                    logging.error(traceback.format_exc())  # Log full traceback
                    print(
                        colored(
                            f"Warning: Failed to close file '{file_path}': {e}",
                            "yellow",
                        )
                    )


@contextmanager
def exclusive_lock(file_path: Path) -> Generator[None, None, None]:
    """
    Convenience context manager to acquire an exclusive lock on a file.

    Parameters:
        file_path (Path): The path to the file to lock.

    Yields:
        None
    """
    with lock_file(file_path, fcntl.LOCK_EX):
        yield


@contextmanager
def shared_lock(file_path: Path) -> Generator[None, None, None]:
    """
    Convenience context manager to acquire a shared lock on a file.

    Parameters:
        file_path (Path): The path to the file to lock.

    Yields:
        None
    """
    with lock_file(file_path, fcntl.LOCK_SH):
        yield
