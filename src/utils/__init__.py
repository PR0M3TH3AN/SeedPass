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
        derive_totp_secret,
        EncryptionMode,
        DEFAULT_ENCRYPTION_MODE,
        TOTP_PURPOSE,
    )
    from .checksum import (
        calculate_checksum,
        verify_checksum,
        json_checksum,
        canonical_json_dumps,
    )
    from .password_prompt import prompt_for_password
    from .input_utils import timed_input
    from .memory_protection import InMemorySecret

    if logger.isEnabledFor(logging.DEBUG):
        logger.info("Modules imported successfully.")
except Exception as e:
    if logger.isEnabledFor(logging.DEBUG):
        logger.error(f"Failed to import one or more modules: {e}", exc_info=True)

__all__ = [
    "derive_key_from_password",
    "derive_key_from_parent_seed",
    "derive_index_key",
    "derive_totp_secret",
    "EncryptionMode",
    "DEFAULT_ENCRYPTION_MODE",
    "TOTP_PURPOSE",
    "calculate_checksum",
    "verify_checksum",
    "json_checksum",
    "canonical_json_dumps",
    "exclusive_lock",
    "shared_lock",
    "prompt_for_password",
    "timed_input",
    "InMemorySecret",
]
