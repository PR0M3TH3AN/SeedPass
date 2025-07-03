# constants.py

import logging
from pathlib import Path

# Instantiate the logger
logger = logging.getLogger(__name__)

# -----------------------------------
# Nostr Relay Connection Settings
# -----------------------------------
MAX_RETRIES = 3  # Maximum number of retries for relay connections
RETRY_DELAY = 5  # Seconds to wait before retrying a failed connection

# -----------------------------------
# Application Directory and Paths
# -----------------------------------
APP_DIR = Path.home() / ".seedpass"
PARENT_SEED_FILE = APP_DIR / "parent_seed.enc"  # Encrypted parent seed

# -----------------------------------
# Checksum Files for Integrity
# -----------------------------------
SCRIPT_CHECKSUM_FILE = (
    APP_DIR / "seedpass_script_checksum.txt"
)  # Checksum for main script


def initialize_app() -> None:
    """Ensure the application directory exists."""
    try:
        APP_DIR.mkdir(exist_ok=True, parents=True)
        if logger.isEnabledFor(logging.DEBUG):
            logger.info(f"Application directory created at {APP_DIR}")
    except Exception as exc:
        if logger.isEnabledFor(logging.DEBUG):
            logger.error(
                f"Failed to create application directory: {exc}", exc_info=True
            )


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
