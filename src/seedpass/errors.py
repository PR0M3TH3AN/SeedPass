"""Compatibility layer for historic exception types."""

from .core.errors import SeedPassError


class VaultLockedError(SeedPassError):
    """Raised when an operation requires an unlocked vault."""

    def __init__(self, message: str = "Vault is locked") -> None:
        super().__init__(message)


__all__ = ["VaultLockedError", "SeedPassError"]
