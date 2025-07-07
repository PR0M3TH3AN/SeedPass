import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

import pytest

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.entry_management import EntryManager
from password_manager.backup import BackupManager
from password_manager.config_manager import ConfigManager
from password_manager.manager import PasswordManager, EncryptionMode


def setup_entry_mgr(tmp_path: Path) -> EntryManager:
    vault, _ = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    cfg_mgr = ConfigManager(vault, tmp_path)
    backup_mgr = BackupManager(tmp_path, cfg_mgr)
    return EntryManager(vault, backup_mgr)


def test_archive_restore_affects_listing_and_search():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        em = setup_entry_mgr(tmp_path)
        idx = em.add_entry("example.com", 8, "alice")

        assert em.list_entries() == [(idx, "example.com", "alice", "", False)]
        assert em.search_entries("example") == [
            (idx, "example.com", "alice", "", False)
        ]

        em.archive_entry(idx)
        assert em.retrieve_entry(idx)["archived"] is True
        assert em.list_entries() == []
        assert em.list_entries(include_archived=True) == [
            (idx, "example.com", "alice", "", True)
        ]
        assert em.search_entries("example") == [(idx, "example.com", "alice", "", True)]

        em.restore_entry(idx)
        assert em.retrieve_entry(idx)["archived"] is False
        assert em.list_entries() == [(idx, "example.com", "alice", "", False)]
        assert em.search_entries("example") == [
            (idx, "example.com", "alice", "", False)
        ]


def test_view_archived_entries_cli(monkeypatch):
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

        idx = entry_mgr.add_entry("example.com", 8)

        monkeypatch.setattr("builtins.input", lambda *_: str(idx))
        pm.handle_archive_entry()
        assert entry_mgr.retrieve_entry(idx)["archived"] is True

        inputs = iter([str(idx), ""])
        monkeypatch.setattr("builtins.input", lambda *_: next(inputs))
        pm.handle_view_archived_entries()
        assert entry_mgr.retrieve_entry(idx)["archived"] is False
