import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from cryptography.fernet import Fernet

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.encryption import EncryptionManager
from password_manager.entry_management import EntryManager
from password_manager.vault import Vault
from password_manager.backup import BackupManager
from password_manager.manager import PasswordManager


class FakePasswordGenerator:
    def generate_password(self, length: int, index: int) -> str:  # noqa: D401
        return f"pw-{index}-{length}"


class FakeNostrClient:
    def __init__(self, *args, **kwargs):
        self.published = []

    def publish_json_to_nostr(self, data: bytes):
        self.published.append(data)
        return True


def test_manager_workflow(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        key = Fernet.generate_key()
        enc_mgr = EncryptionManager(key, tmp_path)
        vault = Vault(enc_mgr, tmp_path)
        entry_mgr = EntryManager(vault, tmp_path)
        backup_mgr = BackupManager(tmp_path)

        monkeypatch.setattr("password_manager.manager.NostrClient", FakeNostrClient)

        pm = PasswordManager.__new__(PasswordManager)
        pm.encryption_manager = enc_mgr
        pm.vault = vault
        pm.entry_manager = entry_mgr
        pm.backup_manager = backup_mgr
        pm.password_generator = FakePasswordGenerator()
        pm.nostr_client = FakeNostrClient()
        pm.fingerprint_dir = tmp_path
        pm.is_dirty = False

        inputs = iter(
            [
                "example.com",
                "",  # username
                "",  # url
                "",  # length (default)
                "0",  # retrieve index
                "0",  # modify index
                "user",  # new username
                "",  # new url
                "",  # blacklist status
            ]
        )
        monkeypatch.setattr("builtins.input", lambda *args, **kwargs: next(inputs))

        pm.handle_add_password()
        assert pm.is_dirty is True
        backups = list(tmp_path.glob("passwords_db_backup_*.json.enc"))
        assert len(backups) == 1
        checksum_file = tmp_path / "seedpass_passwords_db_checksum.txt"
        assert checksum_file.exists()
        checksum_after_add = checksum_file.read_text()
        first_post = pm.nostr_client.published[-1]

        pm.is_dirty = False
        pm.handle_retrieve_entry()
        assert pm.is_dirty is False

        pm.handle_modify_entry()
        assert pm.is_dirty is True
        pm.backup_manager.create_backup()
        backup_dir = tmp_path / "backups"
        backups_mod = list(backup_dir.glob("passwords_db_backup_*.json.enc"))
        assert backups_mod
        checksum_after_modify = checksum_file.read_text()
        assert checksum_after_modify != checksum_after_add
        assert first_post in pm.nostr_client.published
        assert pm.nostr_client.published[-1] != first_post
