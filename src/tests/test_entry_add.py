import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.entry_management import EntryManager
from password_manager.vault import Vault


def test_add_and_retrieve_entry():
    with TemporaryDirectory() as tmpdir:
        vault, enc_mgr = create_vault(Path(tmpdir), TEST_SEED, TEST_PASSWORD)
        entry_mgr = EntryManager(vault, Path(tmpdir))

        index = entry_mgr.add_entry("example.com", 12, "user")
        entry = entry_mgr.retrieve_entry(index)

        assert entry == {
            "website": "example.com",
            "length": 12,
            "username": "user",
            "url": "",
            "blacklisted": False,
        }

        data = enc_mgr.load_json_data(entry_mgr.index_file)
        assert str(index) in data.get("entries", {})
        assert data["entries"][str(index)] == entry
