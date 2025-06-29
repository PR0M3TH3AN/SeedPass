"""Config management for SeedPass profiles."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List

import bcrypt

from password_manager.encryption import EncryptionManager
from nostr.client import DEFAULT_RELAYS as DEFAULT_NOSTR_RELAYS

logger = logging.getLogger(__name__)


class ConfigManager:
    """Manage per-profile configuration encrypted on disk."""

    CONFIG_FILENAME = "seedpass_config.json.enc"

    def __init__(self, encryption_manager: EncryptionManager, fingerprint_dir: Path):
        self.encryption_manager = encryption_manager
        self.fingerprint_dir = fingerprint_dir
        self.config_path = self.fingerprint_dir / self.CONFIG_FILENAME

    def load_config(self) -> dict:
        """Load the configuration file, returning defaults if none exists."""
        if not self.config_path.exists():
            logger.info("Config file not found; returning defaults")
            return {"relays": list(DEFAULT_NOSTR_RELAYS), "pin_hash": ""}
        try:
            data = self.encryption_manager.load_json_data(self.CONFIG_FILENAME)
            if not isinstance(data, dict):
                raise ValueError("Config data must be a dictionary")
            # Ensure defaults for missing keys
            data.setdefault("relays", list(DEFAULT_NOSTR_RELAYS))
            data.setdefault("pin_hash", "")
            return data
        except Exception as exc:
            logger.error(f"Failed to load config: {exc}")
            raise

    def save_config(self, config: dict) -> None:
        """Encrypt and save configuration."""
        try:
            self.encryption_manager.save_json_data(config, self.CONFIG_FILENAME)
        except Exception as exc:
            logger.error(f"Failed to save config: {exc}")
            raise

    def set_relays(self, relays: List[str]) -> None:
        """Update relay list and save."""
        config = self.load_config()
        config["relays"] = relays
        self.save_config(config)

    def set_pin(self, pin: str) -> None:
        """Hash and store the provided PIN."""
        pin_hash = bcrypt.hashpw(pin.encode(), bcrypt.gensalt()).decode()
        config = self.load_config()
        config["pin_hash"] = pin_hash
        self.save_config(config)

    def verify_pin(self, pin: str) -> bool:
        """Check a provided PIN against the stored hash."""
        config = self.load_config()
        stored = config.get("pin_hash", "").encode()
        if not stored:
            return False
        return bcrypt.checkpw(pin.encode(), stored)
