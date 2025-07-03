# password_manager/backup.py

"""
Backup Manager Module

This module implements the BackupManager class, responsible for creating backups,
restoring from backups, and listing available backups for the encrypted password
index file. It ensures data integrity and provides mechanisms to recover from
corrupted or lost data by maintaining timestamped backups.

Ensure that all dependencies are installed and properly configured in your environment.
"""

import logging
import os
import shutil
import time
import traceback
from pathlib import Path
from termcolor import colored

from password_manager.config_manager import ConfigManager

from utils.file_lock import exclusive_lock
from constants import APP_DIR

# Instantiate the logger
logger = logging.getLogger(__name__)


class BackupManager:
    """
    BackupManager Class

    Handles the creation, restoration, and listing of backups for the encrypted password
    index file. Backups are stored in the application directory with
    timestamped filenames to facilitate easy identification and retrieval.
    """

    BACKUP_FILENAME_TEMPLATE = "entries_db_backup_{timestamp}.json.enc"

    def __init__(self, fingerprint_dir: Path, config_manager: ConfigManager):
        """
        Initializes the BackupManager with the fingerprint directory.

        Parameters:
            fingerprint_dir (Path): The directory corresponding to the fingerprint.
            config_manager (ConfigManager): Configuration manager for profile settings.
        """
        self.fingerprint_dir = fingerprint_dir
        self.config_manager = config_manager
        self.backup_dir = self.fingerprint_dir / "backups"
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.index_file = self.fingerprint_dir / "seedpass_entries_db.json.enc"
        logger.debug(
            f"BackupManager initialized with backup directory at {self.backup_dir}"
        )

    def create_backup(self) -> None:
        try:
            index_file = self.index_file
            if not index_file.exists():
                logger.warning("Index file does not exist. No backup created.")
                print(
                    colored(
                        "Warning: Index file does not exist. No backup created.",
                        "yellow",
                    )
                )
                return

            timestamp = int(time.time())
            backup_filename = self.BACKUP_FILENAME_TEMPLATE.format(timestamp=timestamp)
            backup_file = self.backup_dir / backup_filename

            shutil.copy2(index_file, backup_file)
            logger.info(f"Backup created successfully at '{backup_file}'.")
            print(colored(f"Backup created successfully at '{backup_file}'.", "green"))
        except Exception as e:
            logger.error(f"Failed to create backup: {e}", exc_info=True)
            print(colored(f"Error: Failed to create backup: {e}", "red"))

    def restore_latest_backup(self) -> None:
        try:
            backup_files = sorted(
                self.backup_dir.glob("entries_db_backup_*.json.enc"),
                key=lambda x: x.stat().st_mtime,
                reverse=True,
            )

            if not backup_files:
                logger.error("No backup files found to restore.")
                print(colored("Error: No backup files found to restore.", "red"))
                return

            latest_backup = backup_files[0]
            index_file = self.index_file
            shutil.copy2(latest_backup, index_file)
            logger.info(f"Restored the index file from backup '{latest_backup}'.")
            print(
                colored(
                    f"Restored the index file from backup '{latest_backup}'.", "green"
                )
            )
        except Exception as e:
            logger.error(
                f"Failed to restore from backup '{latest_backup}': {e}", exc_info=True
            )
            print(
                colored(
                    f"Error: Failed to restore from backup '{latest_backup}': {e}",
                    "red",
                )
            )

    def list_backups(self) -> None:
        try:
            backup_files = sorted(
                self.backup_dir.glob("entries_db_backup_*.json.enc"),
                key=lambda x: x.stat().st_mtime,
                reverse=True,
            )

            if not backup_files:
                logger.info("No backup files available.")
                print(colored("No backup files available.", "yellow"))
                return

            print(colored("Available Backups:", "cyan"))
            for backup in backup_files:
                creation_time = time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.localtime(backup.stat().st_mtime)
                )
                print(colored(f"- {backup.name} (Created on: {creation_time})", "cyan"))
        except Exception as e:
            logger.error(f"Failed to list backups: {e}", exc_info=True)
            print(colored(f"Error: Failed to list backups: {e}", "red"))

    def restore_backup_by_timestamp(self, timestamp: int) -> None:
        backup_filename = self.BACKUP_FILENAME_TEMPLATE.format(timestamp=timestamp)
        backup_file = self.backup_dir / backup_filename

        if not backup_file.exists():
            logger.error(f"No backup found with timestamp {timestamp}.")
            print(colored(f"Error: No backup found with timestamp {timestamp}.", "red"))
            return

        try:
            with exclusive_lock(backup_file):
                shutil.copy2(backup_file, self.index_file)
            logger.info(f"Restored the index file from backup '{backup_file}'.")
            print(
                colored(
                    f"Restored the index file from backup '{backup_file}'.", "green"
                )
            )
        except Exception as e:
            logger.error(
                f"Failed to restore from backup '{backup_file}': {e}", exc_info=True
            )
            print(
                colored(
                    f"Error: Failed to restore from backup '{backup_file}': {e}", "red"
                )
            )
