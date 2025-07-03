import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import pytest
from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.entry_management import EntryManager
from password_manager.backup import BackupManager
from password_manager.vault import Vault


def test_add_and_retrieve_entry():
    with TemporaryDirectory() as tmpdir:
        vault, enc_mgr = create_vault(Path(tmpdir), TEST_SEED, TEST_PASSWORD)
        backup_mgr = BackupManager(Path(tmpdir))
        entry_mgr = EntryManager(vault, backup_mgr)

        index = entry_mgr.add_entry("example.com", 12, "user")
        entry = entry_mgr.retrieve_entry(index)

        assert entry == {
            "website": "example.com",
            "length": 12,
            "username": "user",
            "url": "",
            "blacklisted": False,
            "type": "password",
            "notes": "",
        }

        data = enc_mgr.load_json_data(entry_mgr.index_file)
        assert str(index) in data.get("entries", {})
        assert data["entries"][str(index)] == entry


@pytest.mark.parametrize(
    "method, expected_type",
    [
        ("add_entry", "password"),
        ("add_totp", "totp"),
        ("add_ssh_key", "ssh"),
        ("add_seed", "seed"),
    ],
)
def test_round_trip_entry_types(method, expected_type):
    with TemporaryDirectory() as tmpdir:
        vault, enc_mgr = create_vault(Path(tmpdir), TEST_SEED, TEST_PASSWORD)
        backup_mgr = BackupManager(Path(tmpdir))
        entry_mgr = EntryManager(vault, backup_mgr)

        if method == "add_entry":
            index = entry_mgr.add_entry("example.com", 8)
        elif method == "add_totp":
            entry_mgr.add_totp("example", TEST_SEED)
            index = 0
        else:
            with pytest.raises(NotImplementedError):
                getattr(entry_mgr, method)()
            index = 0

        entry = entry_mgr.retrieve_entry(index)
        assert entry["type"] == expected_type
        data = enc_mgr.load_json_data(entry_mgr.index_file)
        assert data["entries"][str(index)]["type"] == expected_type


def test_legacy_entry_defaults_to_password():
    with TemporaryDirectory() as tmpdir:
        vault, enc_mgr = create_vault(Path(tmpdir), TEST_SEED, TEST_PASSWORD)
        backup_mgr = BackupManager(Path(tmpdir))
        entry_mgr = EntryManager(vault, backup_mgr)

        index = entry_mgr.add_entry("example.com", 8)

        data = enc_mgr.load_json_data(entry_mgr.index_file)
        data["entries"][str(index)].pop("type", None)
        enc_mgr.save_json_data(data, entry_mgr.index_file)

        loaded = entry_mgr._load_index()
        assert loaded["entries"][str(index)]["type"] == "password"
