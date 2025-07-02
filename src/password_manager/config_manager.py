"""Config management for SeedPass profiles."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional

import getpass

import bcrypt

from password_manager.vault import Vault
from nostr.client import DEFAULT_RELAYS as DEFAULT_NOSTR_RELAYS
from utils.key_derivation import (
    EncryptionMode,
    DEFAULT_ENCRYPTION_MODE,
)
from constants import INACTIVITY_TIMEOUT

logger = logging.getLogger(__name__)


class ConfigManager:
    """Manage per-profile configuration encrypted on disk."""

    CONFIG_FILENAME = "seedpass_config.json.enc"

    def __init__(self, vault: Vault, fingerprint_dir: Path):
        self.vault = vault
        self.fingerprint_dir = fingerprint_dir
        self.config_path = self.fingerprint_dir / self.CONFIG_FILENAME

    def load_config(self, require_pin: bool = True) -> dict:
        """Load the configuration file and optionally verify a stored PIN.

        Parameters
        ----------
        require_pin: bool, default True
            If True and a PIN is configured, prompt the user to enter it and
            verify against the stored hash.
        """
        if not self.config_path.exists():
            logger.info("Config file not found; returning defaults")
            return {
                "relays": list(DEFAULT_NOSTR_RELAYS),
                "pin_hash": "",
                "password_hash": "",
                "encryption_mode": DEFAULT_ENCRYPTION_MODE.value,
                "inactivity_timeout": INACTIVITY_TIMEOUT,
            }
        try:
            data = self.vault.load_config()
            if not isinstance(data, dict):
                raise ValueError("Config data must be a dictionary")
            # Ensure defaults for missing keys
            data.setdefault("relays", list(DEFAULT_NOSTR_RELAYS))
            data.setdefault("pin_hash", "")
            data.setdefault("password_hash", "")
            data.setdefault("encryption_mode", DEFAULT_ENCRYPTION_MODE.value)
            data.setdefault("inactivity_timeout", INACTIVITY_TIMEOUT)

            # Migrate legacy hashed_password.enc if present and password_hash is missing
            legacy_file = self.fingerprint_dir / "hashed_password.enc"
            if not data.get("password_hash") and legacy_file.exists():
                with open(legacy_file, "rb") as f:
                    data["password_hash"] = f.read().decode()
                self.save_config(data)
            if require_pin and data.get("pin_hash"):
                for _ in range(3):
                    pin = getpass.getpass("Enter settings PIN: ").strip()
                    if bcrypt.checkpw(pin.encode(), data["pin_hash"].encode()):
                        break
                    print("Invalid PIN")
                else:
                    raise ValueError("PIN verification failed")
            return data
        except Exception as exc:
            logger.error(f"Failed to load config: {exc}")
            raise

    def save_config(self, config: dict) -> None:
        """Encrypt and save configuration."""
        try:
            self.vault.save_config(config)
        except Exception as exc:
            logger.error(f"Failed to save config: {exc}")
            raise

    def set_relays(self, relays: List[str], require_pin: bool = True) -> None:
        """Update relay list and save."""
        if not relays:
            raise ValueError("At least one Nostr relay must be configured")
        config = self.load_config(require_pin=require_pin)
        config["relays"] = relays
        self.save_config(config)

    def set_pin(self, pin: str) -> None:
        """Hash and store the provided PIN."""
        pin_hash = bcrypt.hashpw(pin.encode(), bcrypt.gensalt()).decode()
        config = self.load_config(require_pin=False)
        config["pin_hash"] = pin_hash
        self.save_config(config)

    def verify_pin(self, pin: str) -> bool:
        """Check a provided PIN against the stored hash without prompting."""
        config = self.load_config(require_pin=False)
        stored = config.get("pin_hash", "").encode()
        if not stored:
            return False
        return bcrypt.checkpw(pin.encode(), stored)

    def change_pin(self, old_pin: str, new_pin: str) -> bool:
        """Update the stored PIN if the old PIN is correct."""
        if self.verify_pin(old_pin):
            self.set_pin(new_pin)
            return True
        return False

    def set_password_hash(self, password_hash: str) -> None:
        """Persist the bcrypt password hash in the config."""
        config = self.load_config(require_pin=False)
        config["password_hash"] = password_hash
        self.save_config(config)

    def set_encryption_mode(self, mode: EncryptionMode) -> None:
        """Persist the selected encryption mode in the config."""
        config = self.load_config(require_pin=False)
        config["encryption_mode"] = mode.value
        self.save_config(config)

    def set_inactivity_timeout(self, timeout_seconds: float) -> None:
        """Persist the inactivity timeout in seconds."""
        if timeout_seconds <= 0:
            raise ValueError("Timeout must be positive")
        config = self.load_config(require_pin=False)
        config["inactivity_timeout"] = timeout_seconds
        self.save_config(config)

    def get_inactivity_timeout(self) -> float:
        """Retrieve the inactivity timeout setting in seconds."""
        config = self.load_config(require_pin=False)
        return float(config.get("inactivity_timeout", INACTIVITY_TIMEOUT))
