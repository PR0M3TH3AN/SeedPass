# nostr/__init__.py

import logging
import traceback

from .logging_config import configure_logging

# Configure logging at the start of the module
configure_logging()

# Initialize the logger for this module
logger = logging.getLogger(__name__)  # Correct logger initialization

try:
    from .client import NostrClient
    logger.info("NostrClient module imported successfully.")
except Exception as e:
    logger.error(f"Failed to import NostrClient module: {e}")
    logger.error(traceback.format_exc())  # Log full traceback

__all__ = ['NostrClient']
