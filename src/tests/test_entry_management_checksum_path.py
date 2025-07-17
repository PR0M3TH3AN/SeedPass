import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass.core.entry_management import EntryManager
from seedpass.core.backup import BackupManager
from seedpass.core.vault import Vault
from seedpass.core.config_manager import ConfigManager


def test_update_checksum_writes_to_expected_path():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        vault, enc_mgr = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, tmp_path)
        backup_mgr = BackupManager(tmp_path, cfg_mgr)
        entry_mgr = EntryManager(vault, backup_mgr)

        # create an empty index file
        vault.save_index({"entries": {}})
        entry_mgr.update_checksum()

        expected = tmp_path / "seedpass_entries_db_checksum.txt"
        assert expected.exists()


def test_backup_index_file_creates_backup_in_directory():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        vault, enc_mgr = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, tmp_path)
        backup_mgr = BackupManager(tmp_path, cfg_mgr)
        entry_mgr = EntryManager(vault, backup_mgr)

        vault.save_index({"entries": {}})
        entry_mgr.backup_manager.create_backup()

        backup_dir = tmp_path / "backups"
        backups = list(backup_dir.glob("entries_db_backup_*.json.enc"))
        assert len(backups) == 1
