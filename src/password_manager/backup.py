# password_manager/backup.py

"""
Backup Manager Module

This module implements the BackupManager class, responsible for creating backups,
restoring from backups, and listing available backups for the encrypted password
index file. It ensures data integrity and provides mechanisms to recover from
corrupted or lost data by maintaining timestamped backups.

Ensure that all dependencies are installed and properly configured in your environment.
"""

import os
import shutil
import time
import logging
import traceback
from pathlib import Path

from colorama import Fore
from termcolor import colored

from constants import APP_DIR, INDEX_FILE
from utils.file_lock import lock_file

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
    f_handler = logging.FileHandler(os.path.join('logs', 'backup_manager.log'))  # Log files will be in 'logs' folder

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

class BackupManager:
    """
    BackupManager Class

    Handles the creation, restoration, and listing of backups for the encrypted
    password index file. Backups are stored in the application directory with
    timestamped filenames to facilitate easy identification and retrieval.
    """

    BACKUP_FILENAME_TEMPLATE = 'passwords_db_backup_{timestamp}.json.enc'

    def __init__(self):
        """
        Initializes the BackupManager with the application directory and index file paths.
        """
        self.app_dir = APP_DIR
        self.index_file = INDEX_FILE
        logging.debug(f"BackupManager initialized with APP_DIR: {self.app_dir} and INDEX_FILE: {self.index_file}")

    def create_backup(self) -> None:
        """
        Creates a timestamped backup of the encrypted password index file.

        The backup file is named using the current Unix timestamp to ensure uniqueness.
        If the index file does not exist, no backup is created.

        Raises:
            Exception: If the backup process fails due to I/O errors.
        """
        if not self.index_file.exists():
            logging.warning("Index file does not exist. No backup created.")
            print(colored("Warning: Index file does not exist. No backup created.", 'yellow'))
            return

        timestamp = int(time.time())
        backup_filename = self.BACKUP_FILENAME_TEMPLATE.format(timestamp=timestamp)
        backup_file = self.app_dir / backup_filename

        try:
            with lock_file(self.index_file, lock_type=fcntl.LOCK_SH):
                shutil.copy2(self.index_file, backup_file)
            logging.info(f"Backup created successfully at '{backup_file}'.")
            print(colored(f"Backup created successfully at '{backup_file}'.", 'green'))
        except Exception as e:
            logging.error(f"Failed to create backup: {e}")
            logging.error(traceback.format_exc())  # Log full traceback
            print(colored(f"Error: Failed to create backup: {e}", 'red'))

    def restore_latest_backup(self) -> None:
        """
        Restores the encrypted password index file from the latest available backup.

        The latest backup is determined based on the Unix timestamp in the backup filenames.
        If no backups are found, an error message is displayed.

        Raises:
            Exception: If the restoration process fails due to I/O errors or missing backups.
        """
        backup_files = sorted(
            self.app_dir.glob('passwords_db_backup_*.json.enc'),
            key=lambda x: x.stat().st_mtime,
            reverse=True
        )

        if not backup_files:
            logging.error("No backup files found to restore.")
            print(colored("Error: No backup files found to restore.", 'red'))
            return

        latest_backup = backup_files[0]
        try:
            with lock_file(latest_backup, lock_type=fcntl.LOCK_SH):
                shutil.copy2(latest_backup, self.index_file)
            logging.info(f"Restored the index file from backup '{latest_backup}'.")
            print(colored(f"Restored the index file from backup '{latest_backup}'.", 'green'))
        except Exception as e:
            logging.error(f"Failed to restore from backup '{latest_backup}': {e}")
            logging.error(traceback.format_exc())  # Log full traceback
            print(colored(f"Error: Failed to restore from backup '{latest_backup}': {e}", 'red'))

    def list_backups(self) -> None:
        """
        Lists all available backups in the application directory, sorted by date.

        Displays the backups with their filenames and creation dates.
        """
        backup_files = sorted(
            self.app_dir.glob('passwords_db_backup_*.json.enc'),
            key=lambda x: x.stat().st_mtime,
            reverse=True
        )

        if not backup_files:
            logging.info("No backup files available.")
            print(colored("No backup files available.", 'yellow'))
            return

        print(colored("Available Backups:", 'cyan'))
        for backup in backup_files:
            creation_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(backup.stat().st_mtime))
            print(colored(f"- {backup.name} (Created on: {creation_time})", 'cyan'))

    def restore_backup_by_timestamp(self, timestamp: int) -> None:
        """
        Restores the encrypted password index file from a backup with the specified timestamp.

        Parameters:
            timestamp (int): The Unix timestamp of the backup to restore.

        Raises:
            Exception: If the restoration process fails due to I/O errors or missing backups.
        """
        backup_filename = self.BACKUP_FILENAME_TEMPLATE.format(timestamp=timestamp)
        backup_file = self.app_dir / backup_filename

        if not backup_file.exists():
            logging.error(f"No backup found with timestamp {timestamp}.")
            print(colored(f"Error: No backup found with timestamp {timestamp}.", 'red'))
            return

        try:
            with lock_file(backup_file, lock_type=fcntl.LOCK_SH):
                shutil.copy2(backup_file, self.index_file)
            logging.info(f"Restored the index file from backup '{backup_file}'.")
            print(colored(f"Restored the index file from backup '{backup_file}'.", 'green'))
        except Exception as e:
            logging.error(f"Failed to restore from backup '{backup_file}': {e}")
            logging.error(traceback.format_exc())  # Log full traceback
            print(colored(f"Error: Failed to restore from backup '{backup_file}': {e}", 'red'))

# Example usage (to be integrated within the PasswordManager class or other modules):

# from password_manager.backup import BackupManager

# backup_manager = BackupManager()
# backup_manager.create_backup()
# backup_manager.restore_latest_backup()
# backup_manager.list_backups()
# backup_manager.restore_backup_by_timestamp(1700000000)  # Example timestamp
