"""TOTP management utilities for SeedPass."""

from __future__ import annotations

import sys
import time
from urllib.parse import quote
from urllib.parse import urlparse, parse_qs, unquote

import pyotp

from utils import key_derivation


class TotpManager:
    """Helper methods for TOTP secrets and codes."""

    @staticmethod
    def derive_secret(seed: str, index: int) -> str:
        """Derive a TOTP secret from a BIP39 seed and index."""
        return key_derivation.derive_totp_secret(seed, index)

    @classmethod
    def current_code(cls, seed: str, index: int, timestamp: int | None = None) -> str:
        """Return the TOTP code for the given seed and index."""
        secret = cls.derive_secret(seed, index)
        totp = pyotp.TOTP(secret)
        if timestamp is None:
            return totp.now()
        return totp.at(timestamp)

    @staticmethod
    def current_code_from_secret(secret: str, timestamp: int | None = None) -> str:
        """Return the TOTP code for a raw secret."""
        totp = pyotp.TOTP(secret)
        return totp.now() if timestamp is None else totp.at(timestamp)

    @staticmethod
    def parse_otpauth(uri: str) -> tuple[str, str, int, int]:
        """Parse an otpauth URI and return (label, secret, period, digits)."""
        if not uri.startswith("otpauth://"):
            raise ValueError("Not an otpauth URI")
        parsed = urlparse(uri)
        label = unquote(parsed.path.lstrip("/"))
        qs = parse_qs(parsed.query)
        secret = qs.get("secret", [""])[0].upper()
        period = int(qs.get("period", ["30"])[0])
        digits = int(qs.get("digits", ["6"])[0])
        if not secret:
            raise ValueError("Missing secret in URI")
        return label, secret, period, digits

    @staticmethod
    def make_otpauth_uri(
        label: str, secret: str, period: int = 30, digits: int = 6
    ) -> str:
        """Construct an otpauth:// URI for use with authenticator apps."""
        label_enc = quote(label)
        return f"otpauth://totp/{label_enc}?secret={secret}&period={period}&digits={digits}"

    @staticmethod
    def time_remaining(period: int = 30, timestamp: int | None = None) -> int:
        """Return seconds remaining until the current TOTP period resets."""
        if timestamp is None:
            timestamp = int(time.time())
        return period - (timestamp % period)

    @classmethod
    def print_progress_bar(cls, period: int = 30) -> None:
        """Print a simple progress bar for the current TOTP period."""
        remaining = cls.time_remaining(period)
        total = period
        bar_len = 20
        while remaining > 0:
            progress = total - remaining
            filled = int(bar_len * progress / total)
            bar = "[" + "#" * filled + "-" * (bar_len - filled) + "]"
            sys.stdout.write(f"\r{bar} {remaining:2d}s")
            sys.stdout.flush()
            time.sleep(1)
            remaining -= 1
        sys.stdout.write("\n")
        sys.stdout.flush()
