"""TOTP management utilities for SeedPass."""

from __future__ import annotations

import os
import sys
import time
import base64
from typing import Union
from urllib.parse import quote
from urllib.parse import urlparse, parse_qs, unquote

import qrcode

import pyotp

from utils import key_derivation


def random_totp_secret(length: int = 20) -> str:
    """Return a random Base32 encoded TOTP secret."""
    return base64.b32encode(os.urandom(length)).decode("ascii").rstrip("=")


class TotpManager:
    """Helper methods for TOTP secrets and codes."""

    @staticmethod
    def derive_secret(seed: Union[str, bytes], index: int) -> str:
        """Derive a TOTP secret from a seed or raw key and index."""
        return key_derivation.derive_totp_secret(seed, index)

    @classmethod
    def current_code(
        cls, seed: Union[str, bytes], index: int, timestamp: int | None = None
    ) -> str:
        """Return the TOTP code for the given seed/key and index."""
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

    @staticmethod
    def print_qr_code(uri: str) -> None:
        """Display a QR code representing the provided URI in the terminal."""
        qr = qrcode.QRCode(border=1)
        qr.add_data(uri)
        qr.make()
        qr.print_ascii(invert=True)
