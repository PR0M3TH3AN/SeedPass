# password_manager/entry_types.py
"""Enumerations for entry types used by SeedPass."""

from enum import Enum


class EntryType(str, Enum):
    """Enumeration of different entry types supported by the manager."""

    PASSWORD = "password"
    TOTP = "totp"
    SSH = "ssh"
    SEED = "seed"
    PGP = "pgp"
    NOSTR = "nostr"
    KEY_VALUE = "key_value"
    MANAGED_ACCOUNT = "managed_account"
