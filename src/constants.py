# constants.py

import logging
from pathlib import Path

# Instantiate the logger
logger = logging.getLogger(__name__)

# -----------------------------------
# Nostr Relay Connection Settings
# -----------------------------------
# Retry fewer times with a shorter wait by default. These values
# act as defaults that can be overridden via ``ConfigManager``
# entries ``nostr_max_retries`` and ``nostr_retry_delay``.
MAX_RETRIES = 2  # Default maximum number of retry attempts
RETRY_DELAY = 1  # Default seconds to wait before retrying
MIN_HEALTHY_RELAYS = 2  # Minimum relays that should return data on startup

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
        logger.debug("Application directory created at %s", APP_DIR)
    except Exception as exc:
        logger.error("Failed to create application directory: %s", exc, exc_info=True)


# -----------------------------------
# Password Generation Constants
# -----------------------------------
DEFAULT_PASSWORD_LENGTH = 16  # Default length for generated passwords
MIN_PASSWORD_LENGTH = 8  # Minimum allowed password length
MAX_PASSWORD_LENGTH = 128  # Maximum allowed password length

# Characters considered safe for passwords when limiting punctuation
SAFE_SPECIAL_CHARS = "!@#$%^*-_+=?"

# Timeout in seconds before the vault locks due to inactivity
INACTIVITY_TIMEOUT = 15 * 60  # 15 minutes

# Duration in seconds that a notification remains active
NOTIFICATION_DURATION = 10

# -----------------------------------
# Additional Constants (if any)
# -----------------------------------
# Add any other constants here as your project expands
DEFAULT_SEED_BACKUP_FILENAME = "parent_seed_backup.enc"
