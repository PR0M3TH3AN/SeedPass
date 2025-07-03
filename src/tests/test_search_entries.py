import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.entry_management import EntryManager
from password_manager.backup import BackupManager
from password_manager.config_manager import ConfigManager


def setup_entry_manager(tmp_path: Path) -> EntryManager:
    vault, _ = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    cfg_mgr = ConfigManager(vault, tmp_path)
    backup_mgr = BackupManager(tmp_path, cfg_mgr)
    return EntryManager(vault, backup_mgr)


def test_search_by_website():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        entry_mgr = setup_entry_manager(tmp_path)

        idx0 = entry_mgr.add_entry("Example.com", 12, "alice")
        entry_mgr.add_entry("Other.com", 8, "bob")

        result = entry_mgr.search_entries("example")
        assert result == [(idx0, "Example.com", "alice", "", False)]


def test_search_by_username():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        entry_mgr = setup_entry_manager(tmp_path)

        entry_mgr.add_entry("Example.com", 12, "alice")
        idx1 = entry_mgr.add_entry("Test.com", 8, "Bob")

        result = entry_mgr.search_entries("bob")
        assert result == [(idx1, "Test.com", "Bob", "", False)]
