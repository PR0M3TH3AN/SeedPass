class VaultLockedError(Exception):
    """Raised when an operation requires an unlocked vault."""

    pass
