import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.entry_management import EntryManager
from password_manager.backup import BackupManager
from password_manager.vault import Vault
from password_manager.config_manager import ConfigManager


def test_list_entries_empty():
    with TemporaryDirectory() as tmpdir:
        vault, enc_mgr = create_vault(Path(tmpdir), TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, Path(tmpdir))
        backup_mgr = BackupManager(Path(tmpdir), cfg_mgr)
        entry_mgr = EntryManager(vault, backup_mgr)

        entries = entry_mgr.list_entries()
        assert entries == []
