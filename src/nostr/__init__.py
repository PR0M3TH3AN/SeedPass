# nostr/__init__.py

import logging
import traceback

try:
    from .client import NostrClient
    logging.info("NostrClient module imported successfully.")
except Exception as e:
    logging.error(f"Failed to import NostrClient module: {e}")
    logging.error(traceback.format_exc())  # Log full traceback

__all__ = ['NostrClient']

