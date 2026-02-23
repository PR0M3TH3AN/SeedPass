from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

from seedpass.core.entry_management import EntryManager
from seedpass.core.backup import BackupManager
from seedpass.core.config_manager import ConfigManager


def _create_entry_manager(tmp_path: Path) -> EntryManager:
    vault, _ = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    cfg_mgr = ConfigManager(vault, tmp_path)
    backup_mgr = BackupManager(tmp_path, cfg_mgr)
    return EntryManager(vault, backup_mgr)


def test_get_entry_summaries_updates_label():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        em = _create_entry_manager(tmp_path)
        idx = em.add_entry("old", 8)

        summaries = em.get_entry_summaries()
        assert summaries == [(idx, "password", "old")]

        em.modify_entry(idx, label="new")
        summaries = em.get_entry_summaries()
        assert summaries == [(idx, "password", "new")]


def test_get_entry_summaries_updates_archive_restore():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        em = _create_entry_manager(tmp_path)
        keep_idx = em.add_entry("keep", 8)
        drop_idx = em.add_entry("drop", 8)

        summaries = em.get_entry_summaries()
        assert [s[0] for s in summaries] == [keep_idx, drop_idx]

        em.archive_entry(drop_idx)
        summaries = em.get_entry_summaries()
        assert [s[0] for s in summaries] == [keep_idx]

        em.restore_entry(drop_idx)
        summaries = em.get_entry_summaries()
        assert [s[0] for s in summaries] == [keep_idx, drop_idx]
