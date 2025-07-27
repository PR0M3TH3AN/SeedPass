import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass.core.entry_management import EntryManager
from seedpass.core.backup import BackupManager
from seedpass.core.config_manager import ConfigManager


def setup_entry_mgr(tmp_path: Path) -> EntryManager:
    vault, _ = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    cfg_mgr = ConfigManager(vault, tmp_path)
    backup_mgr = BackupManager(tmp_path, cfg_mgr)
    return EntryManager(vault, backup_mgr)


def test_add_and_modify_key_value():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        em = setup_entry_mgr(tmp_path)

        idx = em.add_key_value("API", "abc123", notes="token")
        entry = em.retrieve_entry(idx)
        assert entry == {
            "type": "key_value",
            "kind": "key_value",
            "label": "API",
            "value": "abc123",
            "notes": "token",
            "archived": False,
            "custom_fields": [],
            "tags": [],
        }

        em.modify_entry(idx, value="def456")
        updated = em.retrieve_entry(idx)
        assert updated["value"] == "def456"

        results = em.search_entries("def456")
        assert results == []
