import os
import sys
import time
from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.backup import BackupManager
from password_manager.config_manager import ConfigManager


def test_backup_restore_workflow(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        fp_dir = Path(tmpdir)
        vault, enc_mgr = create_vault(fp_dir, TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, fp_dir)
        backup_mgr = BackupManager(fp_dir, cfg_mgr)

        index_file = fp_dir / "seedpass_entries_db.json.enc"

        data1 = {
            "schema_version": 2,
            "entries": {
                "0": {"website": "a", "length": 10, "type": "password", "notes": ""}
            },
        }
        vault.save_index(data1)
        os.utime(index_file, (1, 1))

        monkeypatch.setattr(time, "time", lambda: 1111)
        backup_mgr.create_backup()
        backup1 = fp_dir / "backups" / "entries_db_backup_1111.json.enc"
        assert backup1.exists()
        assert backup1.stat().st_mode & 0o777 == 0o600

        data2 = {
            "schema_version": 2,
            "entries": {
                "0": {"website": "b", "length": 12, "type": "password", "notes": ""}
            },
        }
        vault.save_index(data2)
        os.utime(index_file, (2, 2))

        monkeypatch.setattr(time, "time", lambda: 2222)
        backup_mgr.create_backup()
        backup2 = fp_dir / "backups" / "entries_db_backup_2222.json.enc"
        assert backup2.exists()
        assert backup2.stat().st_mode & 0o777 == 0o600

        vault.save_index({"schema_version": 2, "entries": {"temp": {}}})
        backup_mgr.restore_latest_backup()
        assert vault.load_index()["entries"] == data2["entries"]

        vault.save_index({"schema_version": 2, "entries": {}})
        backup_mgr.restore_backup_by_timestamp(1111)
        assert vault.load_index()["entries"] == data1["entries"]

        backup1.unlink()
        current = vault.load_index()
        backup_mgr.restore_backup_by_timestamp(1111)
        assert vault.load_index() == current
