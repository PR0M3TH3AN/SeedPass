import bcrypt
from pathlib import Path
from tempfile import TemporaryDirectory
from cryptography.fernet import Fernet
import pytest
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.encryption import EncryptionManager
from password_manager.config_manager import ConfigManager
from nostr.client import DEFAULT_RELAYS


def test_config_defaults_and_round_trip():
    with TemporaryDirectory() as tmpdir:
        key = Fernet.generate_key()
        enc_mgr = EncryptionManager(key, Path(tmpdir))
        cfg_mgr = ConfigManager(enc_mgr, Path(tmpdir))

        cfg = cfg_mgr.load_config(require_pin=False)
        assert cfg["relays"] == list(DEFAULT_RELAYS)
        assert cfg["pin_hash"] == ""

        cfg_mgr.set_pin("1234")
        cfg_mgr.set_relays(["wss://example.com"], require_pin=False)

        cfg2 = cfg_mgr.load_config(require_pin=False)
        assert cfg2["relays"] == ["wss://example.com"]
        assert bcrypt.checkpw(b"1234", cfg2["pin_hash"].encode())


def test_pin_verification_and_change():
    with TemporaryDirectory() as tmpdir:
        key = Fernet.generate_key()
        enc_mgr = EncryptionManager(key, Path(tmpdir))
        cfg_mgr = ConfigManager(enc_mgr, Path(tmpdir))

        cfg_mgr.set_pin("1234")
        assert cfg_mgr.verify_pin("1234")
        assert not cfg_mgr.verify_pin("0000")
        assert cfg_mgr.change_pin("1234", "5678")
        assert cfg_mgr.verify_pin("5678")


import json


def test_config_file_encrypted_after_save():
    with TemporaryDirectory() as tmpdir:
        key = Fernet.generate_key()
        enc_mgr = EncryptionManager(key, Path(tmpdir))
        cfg_mgr = ConfigManager(enc_mgr, Path(tmpdir))

        data = {"relays": ["wss://r"], "pin_hash": ""}
        cfg_mgr.save_config(data)

        file_path = Path(tmpdir) / cfg_mgr.CONFIG_FILENAME
        raw = file_path.read_bytes()
        assert raw != json.dumps(data).encode()

        loaded = cfg_mgr.load_config(require_pin=False)
        assert loaded == data


def test_set_relays_persists_changes():
    with TemporaryDirectory() as tmpdir:
        key = Fernet.generate_key()
        enc_mgr = EncryptionManager(key, Path(tmpdir))
        cfg_mgr = ConfigManager(enc_mgr, Path(tmpdir))
        cfg_mgr.set_relays(["wss://custom"], require_pin=False)
        cfg = cfg_mgr.load_config(require_pin=False)
        assert cfg["relays"] == ["wss://custom"]


def test_set_relays_requires_at_least_one():
    with TemporaryDirectory() as tmpdir:
        key = Fernet.generate_key()
        enc_mgr = EncryptionManager(key, Path(tmpdir))
        cfg_mgr = ConfigManager(enc_mgr, Path(tmpdir))
        with pytest.raises(ValueError):
            cfg_mgr.set_relays([], require_pin=False)
