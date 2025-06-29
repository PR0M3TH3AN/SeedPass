import bcrypt
from pathlib import Path
from tempfile import TemporaryDirectory
from cryptography.fernet import Fernet
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
