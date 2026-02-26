import sys
import logging
from unittest.mock import patch
from pathlib import Path
import pytest

sys.path.append(str(Path(__file__).resolve().parents[1]))

from utils.fingerprint import generate_fingerprint

# Sample seed for testing
TEST_SEED = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
EXPECTED_FINGERPRINT = "C557EEC878DFD852"


def test_generate_fingerprint_valid():
    """Test standard successful fingerprint generation."""
    fp = generate_fingerprint(TEST_SEED)
    assert fp is not None
    assert len(fp) == 16
    assert fp.isupper()
    assert fp == EXPECTED_FINGERPRINT


def test_generate_fingerprint_custom_length():
    """Test fingerprint generation with custom length."""
    length = 8
    fp = generate_fingerprint(TEST_SEED, length=length)
    assert fp is not None
    assert len(fp) == length
    assert fp == EXPECTED_FINGERPRINT[:length]


def test_generate_fingerprint_normalization():
    """Test that input is normalized (stripped and lowercased)."""
    messy_seed = "  " + TEST_SEED.upper() + "  "
    fp = generate_fingerprint(messy_seed)
    assert fp == EXPECTED_FINGERPRINT


def test_generate_fingerprint_error_handling(caplog):
    """Test error handling when an exception occurs during generation."""
    # Patch hashlib.sha256 to raise an exception
    with patch("hashlib.sha256", side_effect=Exception("Mocked hashing error")):
        # Ensure we capture logs at ERROR level
        with caplog.at_level(logging.ERROR):
            fp = generate_fingerprint(TEST_SEED)

            # Function should return None on error
            assert fp is None

            # Check that the error was logged
            assert "Failed to generate fingerprint: Mocked hashing error" in caplog.text


def test_generate_fingerprint_invalid_input(caplog):
    """Test handling of invalid input type which raises AttributeError on .strip()."""
    with caplog.at_level(logging.ERROR):
        # Passing None will cause AttributeError: 'NoneType' object has no attribute 'strip'
        fp = generate_fingerprint(None)

        assert fp is None
        assert "Failed to generate fingerprint" in caplog.text
        assert "'NoneType' object has no attribute 'strip'" in caplog.text
