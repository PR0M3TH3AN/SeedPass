# bip85/__init__.py

import logging
import traceback

logger = logging.getLogger(__name__)

try:
    from .bip85 import BIP85

    if logger.isEnabledFor(logging.DEBUG):
        logger.info("BIP85 module imported successfully.")
except Exception as e:
    if logger.isEnabledFor(logging.DEBUG):
        logger.error(f"Failed to import BIP85 module: {e}", exc_info=True)

__all__ = ["BIP85"]
