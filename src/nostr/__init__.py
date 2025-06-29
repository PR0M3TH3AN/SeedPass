# nostr/__init__.py

import logging
import traceback
from .client import NostrClient

# Instantiate the logger
logger = logging.getLogger(__name__)

# Initialize the logger for this module
logger = logging.getLogger(__name__)  # Correct logger initialization

try:
    from .client import NostrClient

    logger.info("NostrClient module imported successfully.")
except Exception as e:
    logger.error(f"Failed to import NostrClient module: {e}")
    logger.error(traceback.format_exc())  # Log full traceback

__all__ = ["NostrClient"]
