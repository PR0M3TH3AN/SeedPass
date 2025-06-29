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

        cfg = cfg_mgr.load_config()
        assert cfg["relays"] == list(DEFAULT_RELAYS)
        assert cfg["pin_hash"] == ""

        cfg_mgr.set_pin("1234")
        cfg_mgr.set_relays(["wss://example.com"])

        cfg2 = cfg_mgr.load_config()
        assert cfg2["relays"] == ["wss://example.com"]
        assert bcrypt.checkpw(b"1234", cfg2["pin_hash"].encode())
