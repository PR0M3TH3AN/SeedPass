# utils/__init__.py

import logging
import traceback

logger = logging.getLogger(__name__)

try:
    from .file_lock import exclusive_lock, shared_lock
    from .key_derivation import (
        derive_key_from_password,
        derive_key_from_parent_seed,
        derive_index_key,
        EncryptionMode,
        DEFAULT_ENCRYPTION_MODE,
    )
    from .checksum import calculate_checksum, verify_checksum
    from .password_prompt import prompt_for_password

    if logger.isEnabledFor(logging.DEBUG):
        logger.info("Modules imported successfully.")
except Exception as e:
    if logger.isEnabledFor(logging.DEBUG):
        logger.error(f"Failed to import one or more modules: {e}", exc_info=True)

__all__ = [
    "derive_key_from_password",
    "derive_key_from_parent_seed",
    "derive_index_key",
    "EncryptionMode",
    "DEFAULT_ENCRYPTION_MODE",
    "calculate_checksum",
    "verify_checksum",
    "exclusive_lock",
    "shared_lock",
    "prompt_for_password",
]
