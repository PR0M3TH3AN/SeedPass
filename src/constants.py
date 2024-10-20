# constants.py

import os
import logging
import sys
from pathlib import Path
import traceback

def configure_logging():
    """
    Configures logging with both file and console handlers.
    Only ERROR and higher-level messages are shown in the terminal, while all messages
    are logged in the log file.
    """
    # Create a custom logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)  # Set to DEBUG for detailed output

    # Create the 'logs' folder if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')

    # Create handlers
    c_handler = logging.StreamHandler(sys.stdout)
    f_handler = logging.FileHandler(os.path.join('logs', 'constants.log'))

    # Set levels: only errors and critical messages will be shown in the console
    c_handler.setLevel(logging.ERROR)  # Console will show ERROR and above
    f_handler.setLevel(logging.DEBUG)  # File will log everything from DEBUG and above

    # Create formatters and add them to handlers, include file and line number in log messages
    c_format = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s [%(filename)s:%(lineno)d]')
    f_format = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s [%(filename)s:%(lineno)d]')

    c_handler.setFormatter(c_format)
    f_handler.setFormatter(f_format)

    # Add handlers to the logger if they are not already added
    if not logger.handlers:
        logger.addHandler(c_handler)
        logger.addHandler(f_handler)

# Configure logging at the start of the module
configure_logging()

# -----------------------------------
# Nostr Relay Connection Settings
# -----------------------------------
MAX_RETRIES = 3          # Maximum number of retries for relay connections
RETRY_DELAY = 5          # Seconds to wait before retrying a failed connection

try:
    # -----------------------------------
    # Application Directory and Paths
    # -----------------------------------
    APP_DIR = Path.home() / '.seedpass'
    APP_DIR.mkdir(exist_ok=True, parents=True)  # Ensure the directory exists
    logging.info(f"Application directory created at {APP_DIR}")
except Exception as e:
    logging.error(f"Failed to create application directory: {e}")
    logging.error(traceback.format_exc())  # Log full traceback

try:
    INDEX_FILE = APP_DIR / 'seedpass_passwords_db.json'        # Encrypted password database
    PARENT_SEED_FILE = APP_DIR / 'parent_seed.enc'    # Encrypted parent seed
    logging.info(f"Index file path set to {INDEX_FILE}")
    logging.info(f"Parent seed file path set to {PARENT_SEED_FILE}")
except Exception as e:
    logging.error(f"Error setting file paths: {e}")
    logging.error(traceback.format_exc())  # Log full traceback

# -----------------------------------
# Checksum Files for Integrity
# -----------------------------------
try:
    SCRIPT_CHECKSUM_FILE = APP_DIR / 'seedpass_script_checksum.txt'      # Checksum for main script
    DATA_CHECKSUM_FILE = APP_DIR / 'seedpass_passwords_checksum.txt'     # Checksum for password data
    logging.info(f"Checksum file paths set: Script {SCRIPT_CHECKSUM_FILE}, Data {DATA_CHECKSUM_FILE}")
except Exception as e:
    logging.error(f"Error setting checksum file paths: {e}")
    logging.error(traceback.format_exc())  # Log full traceback

# -----------------------------------
# Password Generation Constants
# -----------------------------------
DEFAULT_PASSWORD_LENGTH = 16    # Default length for generated passwords
MIN_PASSWORD_LENGTH = 8         # Minimum allowed password length
MAX_PASSWORD_LENGTH = 128       # Maximum allowed password length

# -----------------------------------
# Additional Constants (if any)
# -----------------------------------
# Add any other constants here as your project expands
