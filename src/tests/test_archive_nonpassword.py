from pathlib import Path
from tempfile import TemporaryDirectory
import sys

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.entry_management import EntryManager
from password_manager.backup import BackupManager
from password_manager.config_manager import ConfigManager


def setup_entry_mgr(tmp_path: Path) -> EntryManager:
    vault, _ = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    cfg_mgr = ConfigManager(vault, tmp_path)
    backup_mgr = BackupManager(tmp_path, cfg_mgr)
    return EntryManager(vault, backup_mgr)


def test_archive_nonpassword_list_search():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        em = setup_entry_mgr(tmp_path)
        em.add_totp("Example", TEST_SEED)
        idx = em.search_entries("Example")[0][0]

        assert em.list_entries() == [(idx, "Example", None, None, False)]
        assert em.search_entries("Example") == [(idx, "Example", None, None, False)]

        em.archive_entry(idx)
        assert em.retrieve_entry(idx)["archived"] is True
        assert em.list_entries() == []
        assert em.list_entries(include_archived=True) == [
            (idx, "Example", None, None, True)
        ]
        assert em.search_entries("Example") == [(idx, "Example", None, None, True)]

        em.restore_entry(idx)
        assert em.retrieve_entry(idx)["archived"] is False
        assert em.list_entries() == [(idx, "Example", None, None, False)]
        assert em.search_entries("Example") == [(idx, "Example", None, None, False)]
