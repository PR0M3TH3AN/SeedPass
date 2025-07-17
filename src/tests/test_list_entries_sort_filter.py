import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass.core.entry_management import EntryManager
from seedpass.core.backup import BackupManager
from seedpass.core.config_manager import ConfigManager
from seedpass.core.entry_types import EntryType


def setup_entry_manager(tmp_path: Path) -> EntryManager:
    vault, _ = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    cfg_mgr = ConfigManager(vault, tmp_path)
    backup_mgr = BackupManager(tmp_path, cfg_mgr)
    return EntryManager(vault, backup_mgr)


def test_sort_by_website():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        em = setup_entry_manager(tmp_path)
        idx0 = em.add_entry("b.com", 8, "user1")
        idx1 = em.add_entry("A.com", 8, "user2")
        result = em.list_entries(sort_by="website")
        assert result == [
            (idx1, "A.com", "user2", "", False),
            (idx0, "b.com", "user1", "", False),
        ]


def test_sort_by_username():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        em = setup_entry_manager(tmp_path)
        idx0 = em.add_entry("alpha.com", 8, "Charlie")
        idx1 = em.add_entry("beta.com", 8, "alice")
        result = em.list_entries(sort_by="username")
        assert result == [
            (idx1, "beta.com", "alice", "", False),
            (idx0, "alpha.com", "Charlie", "", False),
        ]


def test_filter_by_type():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        em = setup_entry_manager(tmp_path)
        em.add_entry("site", 8, "user")
        em.add_totp("Example", TEST_SEED)
        result = em.list_entries(filter_kind=EntryType.TOTP.value)
        assert result == [(1, "Example", None, None, False)]
