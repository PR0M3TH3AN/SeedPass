# utils/__init__.py

"""Utility package exports and optional feature handling."""

import logging

logger = logging.getLogger(__name__)

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
    initialize_checksum,
    update_checksum_file,
)
from .password_prompt import prompt_for_password
from .seed_prompt import masked_input, prompt_seed_words
from .input_utils import timed_input
from .memory_protection import InMemorySecret
from .terminal_utils import (
    clear_screen,
    pause,
    clear_and_print_fingerprint,
    clear_header_with_notification,
)
from .atomic_write import atomic_write

# Optional clipboard support
try:  # pragma: no cover - exercised when dependency missing
    from .clipboard import ClipboardUnavailableError, copy_to_clipboard
except Exception as exc:  # pragma: no cover - executed only if pyperclip missing

    class ClipboardUnavailableError(RuntimeError):
        """Stub exception when clipboard support is unavailable."""

    def copy_to_clipboard(*_args, **_kwargs):
        """Stub when clipboard support is unavailable."""
        logger.warning("Clipboard support unavailable: %s", exc)
        raise ClipboardUnavailableError(str(exc))


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
    "initialize_checksum",
    "update_checksum_file",
    "exclusive_lock",
    "shared_lock",
    "prompt_for_password",
    "masked_input",
    "prompt_seed_words",
    "timed_input",
    "InMemorySecret",
    "copy_to_clipboard",
    "ClipboardUnavailableError",
    "clear_screen",
    "clear_and_print_fingerprint",
    "clear_header_with_notification",
    "pause",
    "atomic_write",
]
