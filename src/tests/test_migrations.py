import sys
from pathlib import Path
import pytest
from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.migrations import LATEST_VERSION


def setup(tmp_path: Path):
    vault, enc_mgr = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    return enc_mgr, vault


def test_migrate_v0_to_v1(tmp_path: Path):
    enc_mgr, vault = setup(tmp_path)
    legacy = {"passwords": {"0": {"website": "a", "length": 8}}}
    enc_mgr.save_json_data(legacy)
    data = vault.load_index()
    assert data["schema_version"] == LATEST_VERSION
    assert data["passwords"] == legacy["passwords"]


def test_error_on_future_version(tmp_path: Path):
    enc_mgr, vault = setup(tmp_path)
    future = {"schema_version": LATEST_VERSION + 1, "passwords": {}}
    enc_mgr.save_json_data(future)
    with pytest.raises(ValueError):
        vault.load_index()
