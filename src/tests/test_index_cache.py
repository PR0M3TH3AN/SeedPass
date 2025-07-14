from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from helpers import create_vault, TEST_SEED, TEST_PASSWORD
from password_manager.entry_management import EntryManager
from password_manager.backup import BackupManager
from password_manager.config_manager import ConfigManager


def test_index_caching():
    with TemporaryDirectory() as tmpdir:
        vault, _ = create_vault(Path(tmpdir), TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, Path(tmpdir))
        backup_mgr = BackupManager(Path(tmpdir), cfg_mgr)
        entry_mgr = EntryManager(vault, backup_mgr)

        # create initial entry so the index file exists
        entry_mgr.add_entry("init", 8)
        entry_mgr.clear_cache()

        with patch.object(vault, "load_index", wraps=vault.load_index) as mocked:
            idx = entry_mgr.add_entry("example.com", 8)
            assert mocked.call_count == 1

            entry = entry_mgr.retrieve_entry(idx)
            assert entry["label"] == "example.com"
            assert mocked.call_count == 1

            entry_mgr.clear_cache()
            entry = entry_mgr.retrieve_entry(idx)
            assert entry["label"] == "example.com"
            assert mocked.call_count == 2
