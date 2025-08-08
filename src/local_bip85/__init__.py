# bip85/__init__.py

import logging

logger = logging.getLogger(__name__)

try:
    from .bip85 import BIP85

    logger.info("BIP85 module imported successfully.")
except Exception as e:
    logger.error(f"Failed to import BIP85 module: {e}", exc_info=True)
    BIP85 = None

__all__ = ["BIP85"] if BIP85 is not None else []
