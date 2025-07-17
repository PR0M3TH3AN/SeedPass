import queue
from types import SimpleNamespace
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass.core.manager import PasswordManager, EncryptionMode
from seedpass.core.entry_management import EntryManager
from seedpass.core.backup import BackupManager
from helpers import create_vault, TEST_SEED, TEST_PASSWORD
from seedpass.core.config_manager import ConfigManager


def _make_pm(tmp_path: Path) -> PasswordManager:
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
    pm.nostr_client = SimpleNamespace()
    pm.fingerprint_dir = tmp_path
    pm.notifications = queue.Queue()
    return pm


def test_handle_search_entries_no_query(monkeypatch, tmp_path):
    pm = _make_pm(tmp_path)
    monkeypatch.setattr(
        "seedpass.core.manager.clear_header_with_notification", lambda *a, **k: None
    )
    monkeypatch.setattr("seedpass.core.manager.pause", lambda: None)
    monkeypatch.setattr("builtins.input", lambda *_: "")

    pm.handle_search_entries()
    note = pm.notifications.get_nowait()
    assert note.level == "WARNING"
    assert note.message == "No search string provided."
