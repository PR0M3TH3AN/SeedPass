import os
import sys
import time
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography.fernet import Fernet

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.encryption import EncryptionManager
from password_manager.vault import Vault
from password_manager.backup import BackupManager


def test_backup_restore_workflow(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        fp_dir = Path(tmpdir)
        key = Fernet.generate_key()
        enc_mgr = EncryptionManager(key, fp_dir)
        vault = Vault(enc_mgr, fp_dir)
        backup_mgr = BackupManager(fp_dir)

        index_file = fp_dir / "seedpass_passwords_db.json.enc"

        data1 = {"passwords": {"0": {"website": "a", "length": 10}}}
        vault.save_index(data1)
        os.utime(index_file, (1, 1))

        monkeypatch.setattr(time, "time", lambda: 1111)
        backup_mgr.create_backup()
        backup1 = fp_dir / "backups" / "passwords_db_backup_1111.json.enc"
        assert backup1.exists()
        assert backup1.stat().st_mode & 0o777 == 0o600

        data2 = {"passwords": {"0": {"website": "b", "length": 12}}}
        vault.save_index(data2)
        os.utime(index_file, (2, 2))

        monkeypatch.setattr(time, "time", lambda: 2222)
        backup_mgr.create_backup()
        backup2 = fp_dir / "backups" / "passwords_db_backup_2222.json.enc"
        assert backup2.exists()
        assert backup2.stat().st_mode & 0o777 == 0o600

        vault.save_index({"passwords": {"temp": {}}})
        backup_mgr.restore_latest_backup()
        assert vault.load_index() == data2

        vault.save_index({"passwords": {}})
        backup_mgr.restore_backup_by_timestamp(1111)
        assert vault.load_index() == data1

        backup1.unlink()
        current = vault.load_index()
        backup_mgr.restore_backup_by_timestamp(1111)
        assert vault.load_index() == current
