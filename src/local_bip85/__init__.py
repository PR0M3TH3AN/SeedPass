# bip85/__init__.py

import logging
import traceback

try:
    from .bip85 import BIP85

    logging.info("BIP85 module imported successfully.")
except Exception as e:
    logging.error(f"Failed to import BIP85 module: {e}")
    logging.error(traceback.format_exc())  # Log full traceback

__all__ = ["BIP85"]
