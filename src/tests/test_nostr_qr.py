import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.entry_management import EntryManager
from password_manager.backup import BackupManager
from password_manager.manager import PasswordManager, EncryptionMode, TotpManager
from password_manager.config_manager import ConfigManager
from utils.color_scheme import color_text


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


def test_show_private_key_qr(monkeypatch, capsys):
    """Ensure nsec QR code is shown and output is colored."""
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
        _, nsec = entry_mgr.get_nostr_key_pair(idx, TEST_SEED)

        inputs = iter([str(idx), "q", "k", ""])
        monkeypatch.setattr("builtins.input", lambda *a, **k: next(inputs))
        called = []
        monkeypatch.setattr(
            "password_manager.manager.TotpManager.print_qr_code",
            lambda data: called.append(data),
        )

        pm.handle_retrieve_entry()
        out = capsys.readouterr().out
        assert called == [nsec]
        assert color_text(f"nsec: {nsec}", "deterministic") in out


def test_qr_menu_case_insensitive(monkeypatch):
    """QR menu should appear even if entry type is uppercase."""
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

        # Modify index to use uppercase type/kind
        data = enc_mgr.load_json_data(entry_mgr.index_file)
        data["entries"][str(idx)]["type"] = "NOSTR"
        data["entries"][str(idx)]["kind"] = "NOSTR"
        enc_mgr.save_json_data(data, entry_mgr.index_file)
        entry_mgr._index_cache = None

        inputs = iter([str(idx), "q", "p", ""])
        monkeypatch.setattr("builtins.input", lambda *a, **k: next(inputs))
        called = []
        monkeypatch.setattr(
            "password_manager.manager.TotpManager.print_qr_code",
            lambda data: called.append(data),
        )

        pm.handle_retrieve_entry()
        assert called == [f"nostr:{npub}"]
