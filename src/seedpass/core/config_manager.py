"""Config management for SeedPass profiles."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional

from utils.seed_prompt import masked_input

import bcrypt

from .vault import Vault
from nostr.client import DEFAULT_RELAYS as DEFAULT_NOSTR_RELAYS

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
                "offline_mode": False,
                "pin_hash": "",
                "password_hash": "",
                "inactivity_timeout": INACTIVITY_TIMEOUT,
                "kdf_iterations": 50_000,
                "kdf_mode": "pbkdf2",
                "additional_backup_path": "",
                "backup_interval": 0,
                "secret_mode_enabled": False,
                "clipboard_clear_delay": 45,
                "quick_unlock": False,
                "nostr_max_retries": 2,
                "nostr_retry_delay": 1.0,
                "min_uppercase": 2,
                "min_lowercase": 2,
                "min_digits": 2,
                "min_special": 2,
                "verbose_timing": False,
            }
        try:
            data = self.vault.load_config()
            if not isinstance(data, dict):
                raise ValueError("Config data must be a dictionary")
            # Ensure defaults for missing keys
            data.setdefault("relays", list(DEFAULT_NOSTR_RELAYS))
            data.setdefault("offline_mode", False)
            data.setdefault("pin_hash", "")
            data.setdefault("password_hash", "")
            data.setdefault("inactivity_timeout", INACTIVITY_TIMEOUT)
            data.setdefault("kdf_iterations", 50_000)
            data.setdefault("kdf_mode", "pbkdf2")
            data.setdefault("additional_backup_path", "")
            data.setdefault("backup_interval", 0)
            data.setdefault("secret_mode_enabled", False)
            data.setdefault("clipboard_clear_delay", 45)
            data.setdefault("quick_unlock", False)
            data.setdefault("nostr_max_retries", 2)
            data.setdefault("nostr_retry_delay", 1.0)
            data.setdefault("min_uppercase", 2)
            data.setdefault("min_lowercase", 2)
            data.setdefault("min_digits", 2)
            data.setdefault("min_special", 2)
            data.setdefault("verbose_timing", False)

            # Migrate legacy hashed_password.enc if present and password_hash is missing
            legacy_file = self.fingerprint_dir / "hashed_password.enc"
            if not data.get("password_hash") and legacy_file.exists():
                with open(legacy_file, "rb") as f:
                    data["password_hash"] = f.read().decode()
                self.save_config(data)
            if require_pin and data.get("pin_hash"):
                for _ in range(3):
                    pin = masked_input("Enter settings PIN: ").strip()
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
            config.setdefault("backup_interval", 0)
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

    def set_kdf_iterations(self, iterations: int) -> None:
        """Persist the PBKDF2 iteration count in the config."""
        if iterations <= 0:
            raise ValueError("Iterations must be positive")
        config = self.load_config(require_pin=False)
        config["kdf_iterations"] = int(iterations)
        self.save_config(config)

    def get_kdf_iterations(self) -> int:
        """Retrieve the PBKDF2 iteration count."""
        config = self.load_config(require_pin=False)
        return int(config.get("kdf_iterations", 50_000))

    def set_kdf_mode(self, mode: str) -> None:
        """Persist the key derivation function mode."""
        if mode not in ("pbkdf2", "argon2"):
            raise ValueError("kdf_mode must be 'pbkdf2' or 'argon2'")
        config = self.load_config(require_pin=False)
        config["kdf_mode"] = mode
        self.save_config(config)

    def get_kdf_mode(self) -> str:
        """Retrieve the configured key derivation function."""
        config = self.load_config(require_pin=False)
        return config.get("kdf_mode", "pbkdf2")

    def set_additional_backup_path(self, path: Optional[str]) -> None:
        """Persist an optional additional backup path in the config."""
        config = self.load_config(require_pin=False)
        config["additional_backup_path"] = path or ""
        self.save_config(config)

    def get_additional_backup_path(self) -> Optional[str]:
        """Retrieve the additional backup path if configured."""
        config = self.load_config(require_pin=False)
        value = config.get("additional_backup_path", "")
        return value or None

    def set_secret_mode_enabled(self, enabled: bool) -> None:
        """Persist the secret mode toggle."""
        config = self.load_config(require_pin=False)
        config["secret_mode_enabled"] = bool(enabled)
        self.save_config(config)

    def set_offline_mode(self, enabled: bool) -> None:
        """Persist the offline mode toggle."""
        config = self.load_config(require_pin=False)
        config["offline_mode"] = bool(enabled)
        self.save_config(config)

    def get_secret_mode_enabled(self) -> bool:
        """Retrieve whether secret mode is enabled."""
        config = self.load_config(require_pin=False)
        return bool(config.get("secret_mode_enabled", False))

    def get_offline_mode(self) -> bool:
        """Retrieve the offline mode setting."""
        config = self.load_config(require_pin=False)
        return bool(config.get("offline_mode", False))

    def set_clipboard_clear_delay(self, delay: int) -> None:
        """Persist clipboard clear timeout in seconds."""
        if delay <= 0:
            raise ValueError("Delay must be positive")
        config = self.load_config(require_pin=False)
        config["clipboard_clear_delay"] = int(delay)
        self.save_config(config)

    def get_clipboard_clear_delay(self) -> int:
        """Retrieve clipboard clear delay in seconds."""
        config = self.load_config(require_pin=False)
        return int(config.get("clipboard_clear_delay", 45))

    def set_backup_interval(self, interval: int | float) -> None:
        """Persist the minimum interval in seconds between automatic backups."""
        if interval < 0:
            raise ValueError("Interval cannot be negative")
        config = self.load_config(require_pin=False)
        config["backup_interval"] = interval
        self.save_config(config)

    def get_backup_interval(self) -> float:
        """Retrieve the backup interval in seconds."""
        config = self.load_config(require_pin=False)
        return float(config.get("backup_interval", 0))

    # Password policy settings
    def get_password_policy(self) -> "PasswordPolicy":
        """Return the password complexity policy."""
        from .password_generation import PasswordPolicy

        cfg = self.load_config(require_pin=False)
        return PasswordPolicy(
            min_uppercase=int(cfg.get("min_uppercase", 2)),
            min_lowercase=int(cfg.get("min_lowercase", 2)),
            min_digits=int(cfg.get("min_digits", 2)),
            min_special=int(cfg.get("min_special", 2)),
        )

    def set_min_uppercase(self, count: int) -> None:
        cfg = self.load_config(require_pin=False)
        cfg["min_uppercase"] = int(count)
        self.save_config(cfg)

    def set_min_lowercase(self, count: int) -> None:
        cfg = self.load_config(require_pin=False)
        cfg["min_lowercase"] = int(count)
        self.save_config(cfg)

    def set_min_digits(self, count: int) -> None:
        cfg = self.load_config(require_pin=False)
        cfg["min_digits"] = int(count)
        self.save_config(cfg)

    def set_min_special(self, count: int) -> None:
        cfg = self.load_config(require_pin=False)
        cfg["min_special"] = int(count)
        self.save_config(cfg)

    def set_quick_unlock(self, enabled: bool) -> None:
        """Persist the quick unlock toggle."""
        cfg = self.load_config(require_pin=False)
        cfg["quick_unlock"] = bool(enabled)
        self.save_config(cfg)

    def get_quick_unlock(self) -> bool:
        """Retrieve whether quick unlock is enabled."""
        cfg = self.load_config(require_pin=False)
        return bool(cfg.get("quick_unlock", False))

    def set_nostr_max_retries(self, retries: int) -> None:
        """Persist the maximum number of Nostr retry attempts."""
        if retries < 0:
            raise ValueError("retries cannot be negative")
        cfg = self.load_config(require_pin=False)
        cfg["nostr_max_retries"] = int(retries)
        self.save_config(cfg)

    def get_nostr_max_retries(self) -> int:
        """Retrieve the configured Nostr retry count."""
        cfg = self.load_config(require_pin=False)
        return int(cfg.get("nostr_max_retries", 2))

    def set_nostr_retry_delay(self, delay: float) -> None:
        """Persist the delay between Nostr retry attempts."""
        if delay < 0:
            raise ValueError("delay cannot be negative")
        cfg = self.load_config(require_pin=False)
        cfg["nostr_retry_delay"] = float(delay)
        self.save_config(cfg)

    def get_nostr_retry_delay(self) -> float:
        """Retrieve the delay in seconds between Nostr retries."""
        cfg = self.load_config(require_pin=False)
        return float(cfg.get("nostr_retry_delay", 1.0))

    def set_verbose_timing(self, enabled: bool) -> None:
        cfg = self.load_config(require_pin=False)
        cfg["verbose_timing"] = bool(enabled)
        self.save_config(cfg)

    def get_verbose_timing(self) -> bool:
        cfg = self.load_config(require_pin=False)
        return bool(cfg.get("verbose_timing", False))
