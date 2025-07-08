import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.entry_management import EntryManager
from password_manager.backup import BackupManager
from password_manager.manager import PasswordManager, EncryptionMode, TotpManager
from password_manager.config_manager import ConfigManager


class FakeNostrClient:
    def __init__(self, *args, **kwargs):
        self.published = []

    def publish_snapshot(self, data: bytes):
        self.published.append(data)
        return None, "abcd"


def test_show_qr_for_nostr_keys(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        vault, enc_mgr = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, tmp_path)
        backup_mgr = BackupManager(tmp_path, cfg_mgr)
        entry_mgr = EntryManager(vault, backup_mgr)

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
        pm.secret_mode_enabled = False

        idx = entry_mgr.add_nostr_key("main")
        npub, _ = entry_mgr.get_nostr_key_pair(idx, TEST_SEED)

        inputs = iter([str(idx), "q", "p", ""])
        monkeypatch.setattr("builtins.input", lambda *a, **k: next(inputs))
        called = []
        monkeypatch.setattr(
            "password_manager.manager.TotpManager.print_qr_code",
            lambda data: called.append(data),
        )

        pm.handle_retrieve_entry()
        assert called == [f"nostr:{npub}"]
