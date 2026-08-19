"""Custom exceptions for SeedPass core modules.

This module defines :class:`SeedPassError`, a base exception used across the
core modules. Library code should raise this error instead of terminating the
process with ``sys.exit`` so that callers can handle failures gracefully.

When raised inside the CLI, :class:`SeedPassError` behaves like a Click
exception, displaying a friendly message and exiting with code ``1``.
"""

from click import ClickException
from cryptography.fernet import InvalidToken


class SeedPassError(ClickException):
    """Base exception for SeedPass-related errors."""

    def __init__(self, message: str):
        super().__init__(message)


class DecryptionError(InvalidToken, SeedPassError):
    """Raised when encrypted data cannot be decrypted.

    Subclasses :class:`cryptography.fernet.InvalidToken` so callers expecting
    the cryptography exception continue to work.
    """


class ProfileMismatchError(SeedPassError, ValueError):
    """Raised when a backup belongs to a different profile than the target.

    Distinguished from a generic failure because the caller's correct response
    is different: this is not a corrupt file or a wrong password, and the
    import would in fact succeed. It would just silently re-derive every
    secret from the target profile's seed, so the entries come back with
    different passwords than the backup was taken to preserve.

    Subclasses :class:`ValueError` so existing callers that catch the broader
    error keep working.
    """


__all__ = ["SeedPassError", "DecryptionError", "ProfileMismatchError"]
