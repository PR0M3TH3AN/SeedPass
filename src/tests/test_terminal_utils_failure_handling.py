"""Tests for terminal utility failure handling."""

import logging
import pytest

from utils.terminal_utils import (
    clear_header_with_notification,
    format_profile,
)


class ErrorFingerprintManager:
    def get_name(self, _fingerprint):  # pragma: no cover - helper
        raise ValueError("boom")


class ErrorPM:
    fingerprint_manager = ErrorFingerprintManager()

    def get_current_notification(self):  # pragma: no cover - helper
        raise RuntimeError("bad")


def test_format_profile_reraises(monkeypatch, caplog):
    pm = ErrorPM()
    with caplog.at_level(logging.ERROR):
        with pytest.raises(ValueError):
            format_profile("abc", pm)
    assert "Error retrieving name for fingerprint" in caplog.text


def test_clear_header_with_notification_reraises(caplog):
    pm = ErrorPM()
    with caplog.at_level(logging.ERROR):
        with pytest.raises(RuntimeError):
            clear_header_with_notification(pm)
    assert "Error getting current notification" in caplog.text
