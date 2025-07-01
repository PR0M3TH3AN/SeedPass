import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from cryptography.fernet import Fernet

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.encryption import EncryptionManager
from password_manager.vault import Vault
from password_manager.entry_management import EntryManager


def test_update_checksum_writes_to_expected_path():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        key = Fernet.generate_key()
        enc_mgr = EncryptionManager(key, tmp_path)
        vault = Vault(enc_mgr, tmp_path)
        entry_mgr = EntryManager(vault, tmp_path)

        # create an empty index file
        vault.save_index({"passwords": {}})
        entry_mgr.update_checksum()

        expected = tmp_path / "seedpass_passwords_db_checksum.txt"
        assert expected.exists()


def test_backup_index_file_creates_backup_in_directory():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        key = Fernet.generate_key()
        enc_mgr = EncryptionManager(key, tmp_path)
        vault = Vault(enc_mgr, tmp_path)
        entry_mgr = EntryManager(vault, tmp_path)

        vault.save_index({"passwords": {}})
        entry_mgr.backup_index_file()

        backups = list(tmp_path.glob("passwords_db_backup_*.json.enc"))
        assert len(backups) == 1
