import time
from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

from seedpass.core.backup import BackupManager
from seedpass.core.config_manager import ConfigManager


def test_backup_interval(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        fp_dir = Path(tmpdir)
        vault, _ = create_vault(fp_dir, TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, fp_dir)
        cfg_mgr.set_backup_interval(10)
        backup_mgr = BackupManager(fp_dir, cfg_mgr)

        vault.save_index({"entries": {}})

        monkeypatch.setattr(time, "time", lambda: 1000)
        backup_mgr.create_backup()
        first = fp_dir / "backups" / "entries_db_backup_1000.json.enc"
        assert first.exists()

        monkeypatch.setattr(time, "time", lambda: 1005)
        backup_mgr.create_backup()
        second = fp_dir / "backups" / "entries_db_backup_1005.json.enc"
        assert not second.exists()

        monkeypatch.setattr(time, "time", lambda: 1012)
        backup_mgr.create_backup()
        third = fp_dir / "backups" / "entries_db_backup_1012.json.enc"
        assert third.exists()
