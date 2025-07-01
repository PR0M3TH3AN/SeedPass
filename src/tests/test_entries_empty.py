import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from cryptography.fernet import Fernet

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.encryption import EncryptionManager
from password_manager.entry_management import EntryManager
from password_manager.vault import Vault


def test_list_entries_empty():
    with TemporaryDirectory() as tmpdir:
        key = Fernet.generate_key()
        enc_mgr = EncryptionManager(key, Path(tmpdir))
        vault = Vault(enc_mgr, Path(tmpdir))
        entry_mgr = EntryManager(vault, Path(tmpdir))

        entries = entry_mgr.list_entries()
        assert entries == []
