import sys
from pathlib import Path
import pytest
from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass.core.migrations import LATEST_VERSION


def setup(tmp_path: Path):
    vault, enc_mgr = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    return enc_mgr, vault


def test_migrate_v0_to_v4(tmp_path: Path):
    enc_mgr, vault = setup(tmp_path)
    legacy = {"passwords": {"0": {"website": "a", "length": 8}}}
    enc_mgr.save_json_data(legacy)
    data = vault.load_index()
    assert data["schema_version"] == LATEST_VERSION
    expected_entry = {
        "label": "a",
        "length": 8,
        "type": "password",
        "notes": "",
        "custom_fields": [],
        "origin": "",
        "tags": [],
    }
    assert data["entries"]["0"] == expected_entry


def test_migrate_v1_to_v4(tmp_path: Path):
    enc_mgr, vault = setup(tmp_path)
    legacy = {"schema_version": 1, "passwords": {"0": {"website": "b", "length": 10}}}
    enc_mgr.save_json_data(legacy)
    data = vault.load_index()
    assert data["schema_version"] == LATEST_VERSION
    expected_entry = {
        "label": "b",
        "length": 10,
        "type": "password",
        "notes": "",
        "custom_fields": [],
        "origin": "",
        "tags": [],
    }
    assert data["entries"]["0"] == expected_entry


def test_migrate_v2_to_v4(tmp_path: Path):
    enc_mgr, vault = setup(tmp_path)
    legacy = {
        "schema_version": 2,
        "entries": {
            "0": {"website": "c", "length": 5, "type": "password", "notes": ""}
        },
    }
    enc_mgr.save_json_data(legacy)
    data = vault.load_index()
    assert data["schema_version"] == LATEST_VERSION
    expected_entry = {
        "label": "c",
        "length": 5,
        "type": "password",
        "notes": "",
        "custom_fields": [],
        "origin": "",
        "tags": [],
    }
    assert data["entries"]["0"] == expected_entry


def test_error_on_future_version(tmp_path: Path):
    enc_mgr, vault = setup(tmp_path)
    future = {"schema_version": LATEST_VERSION + 1, "entries": {}}
    enc_mgr.save_json_data(future)
    with pytest.raises(ValueError):
        vault.load_index()


def test_schema_migration_persisted_once(tmp_path: Path):
    enc_mgr, vault = setup(tmp_path)
    legacy = {
        "schema_version": 3,
        "entries": {
            "0": {
                "label": "a",
                "length": 8,
                "type": "password",
                "notes": "",
                "custom_fields": [],
                "origin": "",
            }
        },
    }
    enc_mgr.save_json_data(legacy)
    data, migrated = vault.load_index(return_migration_flag=True)
    assert migrated is True
    assert data["schema_version"] == LATEST_VERSION
    assert data["entries"]["0"]["tags"] == []

    data_again, migrated_again = vault.load_index(return_migration_flag=True)
    assert migrated_again is False
    assert data_again == data
