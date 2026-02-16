import sys
from pathlib import Path
import pytest
from unittest.mock import Mock, MagicMock

# Add src to sys.path
sys.path.append(str(Path(__file__).resolve().parents[1]))

from utils.key_validation import (
    validate_totp_secret,
    validate_ssh_key_pair,
    validate_pgp_private_key,
    validate_nostr_keys,
    validate_seed_phrase,
)

def test_validate_totp_secret_exception(monkeypatch):
    """Test that validate_totp_secret returns False when an exception occurs."""
    monkeypatch.setattr("utils.key_validation.pyotp.TOTP", Mock(side_effect=Exception("TOTP Error")))
    assert validate_totp_secret("any_secret") is False

def test_validate_ssh_key_pair_exception(monkeypatch):
    """Test that validate_ssh_key_pair returns False when an exception occurs."""
    monkeypatch.setattr("utils.key_validation.serialization.load_pem_private_key", Mock(side_effect=Exception("SSH Error")))
    assert validate_ssh_key_pair("priv", "pub") is False

def test_validate_pgp_private_key_exception(monkeypatch):
    """Test that validate_pgp_private_key returns False when an exception occurs."""
    monkeypatch.setattr("utils.key_validation.PGPKey.from_blob", Mock(side_effect=Exception("PGP Error")))
    assert validate_pgp_private_key("priv", "fp") is False

def test_validate_nostr_keys_exception(monkeypatch):
    """Test that validate_nostr_keys returns False when an exception occurs."""
    # The function calls Keys.bech32_to_hex(nsec) first
    monkeypatch.setattr("utils.key_validation.Keys.bech32_to_hex", Mock(side_effect=Exception("Nostr Error")))
    assert validate_nostr_keys("npub", "nsec") is False

def test_validate_seed_phrase_exception(monkeypatch):
    """Test that validate_seed_phrase returns False when an exception occurs."""
    # The function calls Mnemonic("english").check(mnemonic)
    mock_instance = MagicMock()
    mock_instance.check.side_effect = Exception("Seed Error")
    monkeypatch.setattr("utils.key_validation.Mnemonic", Mock(return_value=mock_instance))
    assert validate_seed_phrase("mnemonic") is False
