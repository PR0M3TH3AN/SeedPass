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
from password_manager.config_manager import ConfigManager


def test_add_and_retrieve_entry():
    with TemporaryDirectory() as tmpdir:
        vault, enc_mgr = create_vault(Path(tmpdir), TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, Path(tmpdir))
        backup_mgr = BackupManager(Path(tmpdir), cfg_mgr)
        entry_mgr = EntryManager(vault, backup_mgr)

        custom = [
            {"label": "api", "value": "123", "is_hidden": True},
            {"label": "note", "value": "hello", "is_hidden": False},
        ]

        index = entry_mgr.add_entry("example.com", 12, "user", custom_fields=custom)
        entry = entry_mgr.retrieve_entry(index)

        assert entry == {
            "label": "example.com",
            "length": 12,
            "username": "user",
            "url": "",
            "archived": False,
            "type": "password",
            "kind": "password",
            "notes": "",
            "custom_fields": custom,
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
        cfg_mgr = ConfigManager(vault, Path(tmpdir))
        backup_mgr = BackupManager(Path(tmpdir), cfg_mgr)
        entry_mgr = EntryManager(vault, backup_mgr)

        if method == "add_entry":
            index = entry_mgr.add_entry("example.com", 8)
        elif method == "add_totp":
            entry_mgr.add_totp("example", TEST_SEED)
            index = 0
        else:
            if method == "add_ssh_key":
                index = entry_mgr.add_ssh_key("ssh", TEST_SEED)
            elif method == "add_seed":
                index = entry_mgr.add_seed("seed", TEST_SEED)
            else:
                index = getattr(entry_mgr, method)()

        entry = entry_mgr.retrieve_entry(index)
        assert entry["type"] == expected_type
        assert entry["kind"] == expected_type
        data = enc_mgr.load_json_data(entry_mgr.index_file)
        assert data["entries"][str(index)]["type"] == expected_type
        assert data["entries"][str(index)]["kind"] == expected_type


def test_legacy_entry_defaults_to_password():
    with TemporaryDirectory() as tmpdir:
        vault, enc_mgr = create_vault(Path(tmpdir), TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, Path(tmpdir))
        backup_mgr = BackupManager(Path(tmpdir), cfg_mgr)
        entry_mgr = EntryManager(vault, backup_mgr)

        index = entry_mgr.add_entry("example.com", 8)

        data = enc_mgr.load_json_data(entry_mgr.index_file)
        data["entries"][str(index)].pop("type", None)
        enc_mgr.save_json_data(data, entry_mgr.index_file)

        loaded = entry_mgr._load_index()
        assert loaded["entries"][str(index)]["type"] == "password"


@pytest.mark.parametrize(
    "method,args",
    [
        ("add_entry", ("site.com", 8)),
        ("add_totp", ("totp", TEST_SEED)),
        ("add_ssh_key", ("ssh", TEST_SEED)),
        ("add_pgp_key", ("pgp", TEST_SEED)),
        ("add_nostr_key", ("nostr",)),
        ("add_seed", ("seed", TEST_SEED)),
    ],
)
def test_add_default_archived_false(method, args):
    with TemporaryDirectory() as tmpdir:
        vault, _ = create_vault(Path(tmpdir), TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, Path(tmpdir))
        backup_mgr = BackupManager(Path(tmpdir), cfg_mgr)
        entry_mgr = EntryManager(vault, backup_mgr)

        if method == "add_totp":
            getattr(entry_mgr, method)(*args)
            index = 0
        else:
            index = getattr(entry_mgr, method)(*args)

        entry = entry_mgr.retrieve_entry(index)
        assert entry["archived"] is False
