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

# Master seed word count.
# -----------------------------------
# 12 words = 128 bits, 24 words = 256 bits. The default stays 12: it is
# entirely adequate and every existing profile uses it, so changing the default
# would alter nothing about existing vaults but would surprise. 24 is offered
# because the master seed protects the whole vault and was previously the one
# secret shorter than the seeds derived beneath it, which default to 24
# (entropy audit L2, docs/entropy_audit_2026-07-31.md).
DEFAULT_SEED_WORD_COUNT = 12
SUPPORTED_SEED_WORD_COUNTS = frozenset({12, 24})

# Timeout in seconds before the vault locks due to inactivity
INACTIVITY_TIMEOUT = 15 * 60  # 15 minutes

# Duration in seconds that a notification remains active
NOTIFICATION_DURATION = 10

# -----------------------------------
# GUI Backend Configuration
# -----------------------------------
GUI_BACKEND_CONFIG = {
    "linux": {
        "pkg": "toga-gtk",
        "version": "0.5.2",
        "sha256": "15b346ac1a2584de5effe5e73a3888f055c68c93300aeb111db9d64186b31646",
    },
    "win32": {
        "pkg": "toga-winforms",
        "version": "0.5.2",
        "sha256": "83181309f204bcc4a34709d23fdfd68467ae8ecc39c906d13c661cb9a0ef581b",
    },
    "darwin": {
        "pkg": "toga-cocoa",
        "version": "0.5.2",
        "sha256": "a4d5d1546bf92372a6fb1b450164735fb107b2ee69d15bf87421fec3c78465f9",
    },
}

# -----------------------------------
# Additional Constants (if any)
# -----------------------------------
# Add any other constants here as your project expands
DEFAULT_SEED_BACKUP_FILENAME = "parent_seed_backup.enc"
