import bcrypt
from pathlib import Path
from tempfile import TemporaryDirectory
import pytest
from helpers import create_vault, TEST_SEED, TEST_PASSWORD
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.config_manager import ConfigManager
from password_manager.vault import Vault
from nostr.client import DEFAULT_RELAYS
from constants import INACTIVITY_TIMEOUT


def test_config_defaults_and_round_trip():
    with TemporaryDirectory() as tmpdir:
        vault, enc_mgr = create_vault(Path(tmpdir), TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, Path(tmpdir))

        cfg = cfg_mgr.load_config(require_pin=False)
        assert cfg["relays"] == list(DEFAULT_RELAYS)
        assert cfg["pin_hash"] == ""
        assert cfg["password_hash"] == ""
        assert cfg["additional_backup_path"] == ""

        cfg_mgr.set_pin("1234")
        cfg_mgr.set_relays(["wss://example.com"], require_pin=False)

        cfg2 = cfg_mgr.load_config(require_pin=False)
        assert cfg2["relays"] == ["wss://example.com"]
        assert bcrypt.checkpw(b"1234", cfg2["pin_hash"].encode())


def test_pin_verification_and_change():
    with TemporaryDirectory() as tmpdir:
        vault, enc_mgr = create_vault(Path(tmpdir), TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, Path(tmpdir))

        cfg_mgr.set_pin("1234")
        assert cfg_mgr.verify_pin("1234")
        assert not cfg_mgr.verify_pin("0000")
        assert cfg_mgr.change_pin("1234", "5678")
        assert cfg_mgr.verify_pin("5678")


import json


def test_config_file_encrypted_after_save():
    with TemporaryDirectory() as tmpdir:
        vault, enc_mgr = create_vault(Path(tmpdir), TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, Path(tmpdir))

        data = {"relays": ["wss://r"], "pin_hash": ""}
        cfg_mgr.save_config(data)

        file_path = Path(tmpdir) / cfg_mgr.CONFIG_FILENAME
        raw = file_path.read_bytes()
        assert raw != json.dumps(data).encode()

        loaded = cfg_mgr.load_config(require_pin=False)
        assert loaded["relays"] == data["relays"]
        assert loaded["pin_hash"] == data["pin_hash"]
        assert loaded["password_hash"] == ""


def test_set_relays_persists_changes():
    with TemporaryDirectory() as tmpdir:
        vault, enc_mgr = create_vault(Path(tmpdir), TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, Path(tmpdir))
        cfg_mgr.set_relays(["wss://custom"], require_pin=False)
        cfg = cfg_mgr.load_config(require_pin=False)
        assert cfg["relays"] == ["wss://custom"]


def test_set_relays_requires_at_least_one():
    with TemporaryDirectory() as tmpdir:
        vault, enc_mgr = create_vault(Path(tmpdir), TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, Path(tmpdir))
        with pytest.raises(ValueError):
            cfg_mgr.set_relays([], require_pin=False)


def test_inactivity_timeout_round_trip():
    with TemporaryDirectory() as tmpdir:
        vault, enc_mgr = create_vault(Path(tmpdir), TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, Path(tmpdir))

        cfg = cfg_mgr.load_config(require_pin=False)
        assert cfg["inactivity_timeout"] == INACTIVITY_TIMEOUT

        cfg_mgr.set_inactivity_timeout(123)
        cfg2 = cfg_mgr.load_config(require_pin=False)
        assert cfg2["inactivity_timeout"] == 123


def test_password_hash_migrates_from_file(tmp_path):
    vault, enc_mgr = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    cfg_mgr = ConfigManager(vault, tmp_path)

    # save legacy config without password_hash
    legacy_cfg = {"relays": ["wss://r"], "pin_hash": ""}
    cfg_mgr.save_config(legacy_cfg)

    hashed = bcrypt.hashpw(b"pw", bcrypt.gensalt())
    (tmp_path / "hashed_password.enc").write_bytes(hashed)

    cfg = cfg_mgr.load_config(require_pin=False)
    assert cfg["password_hash"] == hashed.decode()
    # subsequent loads should read from config
    (tmp_path / "hashed_password.enc").unlink()
    cfg2 = cfg_mgr.load_config(require_pin=False)
    assert cfg2["password_hash"] == hashed.decode()


def test_additional_backup_path_round_trip():
    with TemporaryDirectory() as tmpdir:
        vault, enc_mgr = create_vault(Path(tmpdir), TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, Path(tmpdir))

        # default should be empty string
        assert cfg_mgr.load_config(require_pin=False)["additional_backup_path"] == ""

        cfg_mgr.set_additional_backup_path("/tmp/my_backups")
        cfg = cfg_mgr.load_config(require_pin=False)
        assert cfg["additional_backup_path"] == "/tmp/my_backups"
        assert cfg_mgr.get_additional_backup_path() == "/tmp/my_backups"

        cfg_mgr.set_additional_backup_path(None)
        cfg2 = cfg_mgr.load_config(require_pin=False)
        assert cfg2["additional_backup_path"] == ""


def test_secret_mode_round_trip():
    with TemporaryDirectory() as tmpdir:
        vault, enc_mgr = create_vault(Path(tmpdir), TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, Path(tmpdir))

        cfg = cfg_mgr.load_config(require_pin=False)
        assert cfg["secret_mode_enabled"] is False
        assert cfg["clipboard_clear_delay"] == 45

        cfg_mgr.set_secret_mode_enabled(True)
        cfg_mgr.set_clipboard_clear_delay(99)
        cfg2 = cfg_mgr.load_config(require_pin=False)
        assert cfg2["secret_mode_enabled"] is True
        assert cfg2["clipboard_clear_delay"] == 99
