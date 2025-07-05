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
            "schema_version": 3,
            "entries": {
                "0": {
                    "label": "a",
                    "length": 10,
                    "type": "password",
                    "kind": "password",
                    "notes": "",
                    "custom_fields": [],
                    "origin": "",
                }
            },
        }
        vault.save_index(data1)
        os.utime(index_file, (1, 1))

        monkeypatch.setattr(time, "time", lambda: 1111)
        backup_mgr.create_backup()
        backup1 = fp_dir / "backups" / "entries_db_backup_1111.json.enc"
        assert backup1.exists()
        if os.name != "nt":
            assert backup1.stat().st_mode & 0o777 == 0o600

        data2 = {
            "schema_version": 3,
            "entries": {
                "0": {
                    "label": "b",
                    "length": 12,
                    "type": "password",
                    "kind": "password",
                    "notes": "",
                    "custom_fields": [],
                    "origin": "",
                }
            },
        }
        vault.save_index(data2)
        os.utime(index_file, (2, 2))

        monkeypatch.setattr(time, "time", lambda: 2222)
        backup_mgr.create_backup()
        backup2 = fp_dir / "backups" / "entries_db_backup_2222.json.enc"
        assert backup2.exists()
        if os.name != "nt":
            assert backup2.stat().st_mode & 0o777 == 0o600

        vault.save_index({"schema_version": 3, "entries": {"temp": {}}})
        backup_mgr.restore_latest_backup()
        assert vault.load_index()["entries"] == data2["entries"]

        vault.save_index({"schema_version": 3, "entries": {}})
        backup_mgr.restore_backup_by_timestamp(1111)
        assert vault.load_index()["entries"] == data1["entries"]

        backup1.unlink()
        current = vault.load_index()
        backup_mgr.restore_backup_by_timestamp(1111)
        assert vault.load_index() == current


def test_additional_backup_location(monkeypatch):
    with TemporaryDirectory() as tmpdir, TemporaryDirectory() as extra:
        fp_dir = Path(tmpdir)
        vault, enc_mgr = create_vault(fp_dir, TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, fp_dir)
        cfg_mgr.set_additional_backup_path(extra)
        backup_mgr = BackupManager(fp_dir, cfg_mgr)

        vault.save_index({"schema_version": 3, "entries": {"a": {}}})

        monkeypatch.setattr(time, "time", lambda: 3333)
        backup_mgr.create_backup()

        backup = fp_dir / "backups" / "entries_db_backup_3333.json.enc"
        assert backup.exists()

        extra_file = Path(extra) / f"{fp_dir.name}_entries_db_backup_3333.json.enc"
        assert extra_file.exists()
        if os.name != "nt":
            assert extra_file.stat().st_mode & 0o777 == 0o600
