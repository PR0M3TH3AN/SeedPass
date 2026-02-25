from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import queue

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

from seedpass.core.entry_management import EntryManager
from seedpass.core.backup import BackupManager
from seedpass.core.config_manager import ConfigManager
from seedpass.core.manager import PasswordManager, EncryptionMode


def test_get_entry_summaries_excludes_archived_and_view_handler(monkeypatch, capsys):
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
        pm.nostr_client = SimpleNamespace()
        pm.fingerprint_dir = tmp_path
        pm.is_dirty = False
        pm.notifications = queue.Queue()

        active_idx = entry_mgr.add_entry("active.com", 8)
        archived_idx = entry_mgr.add_entry("archived.com", 8)
        entry_mgr.archive_entry(archived_idx)

        summaries = entry_mgr.get_entry_summaries()
        assert [s[0] for s in summaries] == [active_idx]
        for idx, _, _ in summaries:
            assert entry_mgr.retrieve_entry(idx)["archived"] is False

        summaries_all = entry_mgr.get_entry_summaries(include_archived=True)
        assert [s[0] for s in summaries_all] == [active_idx, archived_idx]

        monkeypatch.setattr("builtins.input", lambda *_: "")
        pm.handle_view_archived_entries()
        out = capsys.readouterr().out
        assert "archived.com" in out
        assert "active.com" not in out
