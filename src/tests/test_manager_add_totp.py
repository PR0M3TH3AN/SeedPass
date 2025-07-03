import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.entry_management import EntryManager
from password_manager.backup import BackupManager
from password_manager.manager import PasswordManager, EncryptionMode


class FakeNostrClient:
    def __init__(self, *args, **kwargs):
        self.published = []

    def publish_snapshot(self, data: bytes):
        self.published.append(data)
        return None, "abcd"


def test_handle_add_totp(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        vault, enc_mgr = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
        entry_mgr = EntryManager(vault, tmp_path)
        backup_mgr = BackupManager(tmp_path)

        pm = PasswordManager.__new__(PasswordManager)
        pm.encryption_mode = EncryptionMode.SEED_ONLY
        pm.encryption_manager = enc_mgr
        pm.vault = vault
        pm.entry_manager = entry_mgr
        pm.backup_manager = backup_mgr
        pm.parent_seed = TEST_SEED
        pm.nostr_client = FakeNostrClient()
        pm.fingerprint_dir = tmp_path
        pm.is_dirty = False

        inputs = iter(
            [
                "Example",  # label
                "",  # period
                "",  # digits
            ]
        )
        monkeypatch.setattr("builtins.input", lambda *args, **kwargs: next(inputs))
        monkeypatch.setattr(pm, "sync_vault", lambda: None)

        pm.handle_add_totp()

        entry = entry_mgr.retrieve_entry(0)
        assert entry == {
            "type": "totp",
            "label": "Example",
            "index": 0,
            "period": 30,
            "digits": 6,
        }
