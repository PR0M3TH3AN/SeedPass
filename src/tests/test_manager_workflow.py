import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass.core.entry_management import EntryManager
from seedpass.core.vault import Vault
from seedpass.core.backup import BackupManager
from seedpass.core.manager import PasswordManager, EncryptionMode
from seedpass.core.config_manager import ConfigManager


class FakePasswordGenerator:
    def generate_password(self, length: int, index: int) -> str:  # noqa: D401
        return f"pw-{index}-{length}"


class FakeNostrClient:
    def __init__(self, *args, **kwargs):
        self.published = []

    def publish_snapshot(self, data: bytes):
        self.published.append(data)
        return None, "abcd"


def test_manager_workflow(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        vault, enc_mgr = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, tmp_path)
        backup_mgr = BackupManager(tmp_path, cfg_mgr)
        entry_mgr = EntryManager(vault, backup_mgr)

        monkeypatch.setattr("seedpass.core.manager.NostrClient", FakeNostrClient)

        pm = PasswordManager.__new__(PasswordManager)
        pm.encryption_mode = EncryptionMode.SEED_ONLY
        pm.encryption_manager = enc_mgr
        pm.vault = vault
        pm.entry_manager = entry_mgr
        pm.backup_manager = backup_mgr
        pm.password_generator = FakePasswordGenerator()
        pm.nostr_client = FakeNostrClient()
        pm.fingerprint_dir = tmp_path
        pm.is_dirty = False
        pm.secret_mode_enabled = False

        inputs = iter(
            [
                "a",  # advanced mode
                "example.com",
                "",  # username
                "",  # url
                "",  # notes
                "",  # tags
                "n",  # add custom field
                "",  # length (default)
                "",  # include special default
                "",  # allowed special default
                "",  # special mode default
                "",  # exclude ambiguous default
                "",  # min uppercase
                "",  # min lowercase
                "",  # min digits
                "",  # min special
                "0",  # retrieve index
                "",  # no action in entry menu
                "0",  # modify index
                "",  # new label
                "user",  # new username
                "",  # new url
                "",  # archive status
                "",  # new notes
                "n",  # edit custom fields
                "",  # tags keep
            ]
        )
        monkeypatch.setattr("builtins.input", lambda *args, **kwargs: next(inputs))

        monkeypatch.setattr(
            pm,
            "start_background_vault_sync",
            lambda *a, **k: pm.sync_vault(*a, **k),
        )

        pm.handle_add_password()
        assert pm.is_dirty is False
        backups = list((tmp_path / "backups").glob("entries_db_backup_*.json.enc"))
        assert len(backups) == 1
        checksum_file = tmp_path / "seedpass_entries_db_checksum.txt"
        assert checksum_file.exists()
        checksum_after_add = checksum_file.read_text()
        first_post = pm.nostr_client.published[-1]

        pm.is_dirty = False
        pm.handle_retrieve_entry()
        assert pm.is_dirty is False

        pm.handle_modify_entry()
        assert pm.is_dirty is False
        pm.backup_manager.create_backup()
        backup_dir = tmp_path / "backups"
        backups_mod = list(backup_dir.glob("entries_db_backup_*.json.enc"))
        assert backups_mod
        checksum_after_modify = checksum_file.read_text()
        assert checksum_after_modify != checksum_after_add
        assert first_post in pm.nostr_client.published
        assert pm.nostr_client.published[-1] != first_post
