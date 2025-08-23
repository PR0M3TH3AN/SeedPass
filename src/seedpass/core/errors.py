"""Custom exceptions for SeedPass core modules.

This module defines :class:`SeedPassError`, a base exception used across the
core modules. Library code should raise this error instead of terminating the
process with ``sys.exit`` so that callers can handle failures gracefully.

When raised inside the CLI, :class:`SeedPassError` behaves like a Click
exception, displaying a friendly message and exiting with code ``1``.
"""

from click import ClickException


class SeedPassError(ClickException):
    """Base exception for SeedPass-related errors."""

    def __init__(self, message: str):
        super().__init__(message)


class DecryptionError(SeedPassError):
    """Raised when encrypted data cannot be decrypted."""


__all__ = ["SeedPassError", "DecryptionError"]
