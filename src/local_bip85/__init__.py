# bip85/__init__.py

import logging

logger = logging.getLogger(__name__)

try:
    from .bip85 import BIP85
except Exception as exc:
    logger.error("Failed to import BIP85 module: %s", exc, exc_info=True)
    raise ImportError(
        "BIP85 dependencies are missing. Install 'bip_utils', 'cryptography', and 'colorama'."
    ) from exc

__all__ = ["BIP85"]
