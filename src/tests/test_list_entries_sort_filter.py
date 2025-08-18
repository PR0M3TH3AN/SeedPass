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


def test_sort_by_label():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        em = setup_entry_manager(tmp_path)
        idx0 = em.add_entry("b.com", 8, "user1")
        idx1 = em.add_entry("A.com", 8, "user2")
        result = em.list_entries(sort_by="label")
        assert result == [
            (idx1, "A.com", "user2", "", False),
            (idx0, "b.com", "user1", "", False),
        ]


def test_sort_by_updated():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        em = setup_entry_manager(tmp_path)
        idx0 = em.add_entry("alpha.com", 8, "u0")
        idx1 = em.add_entry("beta.com", 8, "u1")

        data = em._load_index(force_reload=True)
        data["entries"][str(idx0)]["updated"] = 1
        data["entries"][str(idx1)]["updated"] = 2
        em._save_index(data)

        result = em.list_entries(sort_by="updated")
        assert result == [
            (idx1, "beta.com", "u1", "", False),
            (idx0, "alpha.com", "u0", "", False),
        ]


def test_filter_by_type():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        em = setup_entry_manager(tmp_path)
        em.add_entry("site", 8, "user")
        em.add_totp("Example", TEST_SEED)
        result = em.list_entries(filter_kinds=[EntryType.TOTP.value])
        assert result == [(1, "Example", None, None, False)]
