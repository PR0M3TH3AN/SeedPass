# constants.py

import os
import logging
import sys
from pathlib import Path
import traceback

# Instantiate the logger
logger = logging.getLogger(__name__)

# -----------------------------------
# Nostr Relay Connection Settings
# -----------------------------------
MAX_RETRIES = 3  # Maximum number of retries for relay connections
RETRY_DELAY = 5  # Seconds to wait before retrying a failed connection

try:
    # -----------------------------------
    # Application Directory and Paths
    # -----------------------------------
    APP_DIR = Path.home() / ".seedpass"
    APP_DIR.mkdir(exist_ok=True, parents=True)  # Ensure the directory exists
    logging.info(f"Application directory created at {APP_DIR}")
except Exception as e:
    logging.error(f"Failed to create application directory: {e}")
    logging.error(traceback.format_exc())  # Log full traceback

try:
    PARENT_SEED_FILE = APP_DIR / "parent_seed.enc"  # Encrypted parent seed
    logging.info(f"Parent seed file path set to {PARENT_SEED_FILE}")
except Exception as e:
    logging.error(f"Error setting file paths: {e}")
    logging.error(traceback.format_exc())  # Log full traceback

# -----------------------------------
# Checksum Files for Integrity
# -----------------------------------
try:
    SCRIPT_CHECKSUM_FILE = (
        APP_DIR / "seedpass_script_checksum.txt"
    )  # Checksum for main script
    logging.info(f"Checksum file path set: Script {SCRIPT_CHECKSUM_FILE}")
except Exception as e:
    logging.error(f"Error setting checksum file paths: {e}")
    logging.error(traceback.format_exc())  # Log full traceback

# -----------------------------------
# Password Generation Constants
# -----------------------------------
DEFAULT_PASSWORD_LENGTH = 16  # Default length for generated passwords
MIN_PASSWORD_LENGTH = 8  # Minimum allowed password length
MAX_PASSWORD_LENGTH = 128  # Maximum allowed password length

# Timeout in seconds before the vault locks due to inactivity
INACTIVITY_TIMEOUT = 15 * 60  # 15 minutes

# -----------------------------------
# Additional Constants (if any)
# -----------------------------------
# Add any other constants here as your project expands
DEFAULT_SEED_BACKUP_FILENAME = "parent_seed_backup.enc"
