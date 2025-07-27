import time
from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

from seedpass.core.entry_management import EntryManager
from seedpass.core.backup import BackupManager
from seedpass.core.config_manager import ConfigManager


def test_entry_manager_additional_backup(monkeypatch):
    with TemporaryDirectory() as tmpdir, TemporaryDirectory() as extra:
        fp_dir = Path(tmpdir)
        vault, _ = create_vault(fp_dir, TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, fp_dir)
        cfg_mgr.set_additional_backup_path(extra)
        backup_mgr = BackupManager(fp_dir, cfg_mgr)
        entry_mgr = EntryManager(vault, backup_mgr)

        monkeypatch.setattr(time, "time", lambda: 1111)
        entry_mgr.add_entry("example.com", 12)

        backup = fp_dir / "backups" / "entries_db_backup_1111.json.enc"
        extra_file = Path(extra) / f"{fp_dir.name}_entries_db_backup_1111.json.enc"
        assert backup.exists()
        assert extra_file.exists()

        cfg_mgr.set_additional_backup_path(None)

        monkeypatch.setattr(time, "time", lambda: 2222)
        entry_mgr.add_entry("example.org", 8)

        backup2 = fp_dir / "backups" / "entries_db_backup_2222.json.enc"
        assert backup2.exists()
        extra_file2 = Path(extra) / f"{fp_dir.name}_entries_db_backup_2222.json.enc"
        assert not extra_file2.exists()
