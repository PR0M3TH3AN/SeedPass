import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from cryptography.fernet import Fernet

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.encryption import EncryptionManager
from password_manager.entry_management import EntryManager


def test_add_and_retrieve_entry():
    with TemporaryDirectory() as tmpdir:
        key = Fernet.generate_key()
        enc_mgr = EncryptionManager(key, Path(tmpdir))
        entry_mgr = EntryManager(enc_mgr, Path(tmpdir))

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
        assert str(index) in data.get("passwords", {})
        assert data["passwords"][str(index)] == entry
