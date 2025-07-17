import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass.core.entry_management import EntryManager
from seedpass.core.backup import BackupManager
from seedpass.core.config_manager import ConfigManager


def setup_entry_manager(tmp_path: Path) -> EntryManager:
    vault, _ = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    cfg_mgr = ConfigManager(vault, tmp_path)
    backup_mgr = BackupManager(tmp_path, cfg_mgr)
    return EntryManager(vault, backup_mgr)


def test_tags_persist_on_new_entry():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        entry_mgr = setup_entry_manager(tmp_path)

        idx = entry_mgr.add_entry("Site", 8, tags=["work"])

        # Reinitialize to simulate application restart
        entry_mgr = setup_entry_manager(tmp_path)

        result = entry_mgr.search_entries("work")
        assert result == [(idx, "Site", "", "", False)]


def test_tags_persist_after_modify():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        entry_mgr = setup_entry_manager(tmp_path)

        idx = entry_mgr.add_entry("Site", 8)
        entry_mgr.modify_entry(idx, tags=["personal"])

        # Ensure tag searchable before reload
        assert entry_mgr.search_entries("personal") == [(idx, "Site", "", "", False)]

        # Reinitialize to simulate application restart
        entry_mgr = setup_entry_manager(tmp_path)
        result = entry_mgr.search_entries("personal")
        assert result == [(idx, "Site", "", "", False)]
