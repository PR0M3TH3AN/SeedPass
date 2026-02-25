from pathlib import Path

import main
from helpers import create_vault, TEST_SEED, TEST_PASSWORD
from seedpass.core.entry_management import EntryManager
from seedpass.core.backup import BackupManager
from seedpass.core.config_manager import ConfigManager
from seedpass.core.manager import PasswordManager, EncryptionMode


def _init_pm(dir_path: Path, client) -> PasswordManager:
    vault, enc_mgr = create_vault(dir_path, TEST_SEED, TEST_PASSWORD)
    cfg_mgr = ConfigManager(vault, dir_path)
    backup_mgr = BackupManager(dir_path, cfg_mgr)
    entry_mgr = EntryManager(vault, backup_mgr)

    pm = PasswordManager.__new__(PasswordManager)
    pm.encryption_mode = EncryptionMode.SEED_ONLY
    pm.encryption_manager = enc_mgr
    pm.vault = vault
    pm.entry_manager = entry_mgr
    pm.backup_manager = backup_mgr
    pm.config_manager = cfg_mgr
    pm.nostr_client = client
    pm.fingerprint_dir = dir_path
    pm.current_fingerprint = "fp"
    pm.is_dirty = False
    return pm


def test_restore_flow_from_snapshot(monkeypatch, tmp_path, make_dummy_nostr_client):
    client, relay = make_dummy_nostr_client(tmp_path / "srv")

    dir_a = tmp_path / "A"
    dir_b = tmp_path / "B"
    dir_a.mkdir()
    dir_b.mkdir()

    pm_a = _init_pm(dir_a, client)
    pm_a.entry_manager.add_entry("site1", 12)
    pm_a.sync_vault()
    assert relay.manifests

    pm_b = _init_pm(dir_b, client)
    monkeypatch.setattr(main, "pause", lambda *a, **k: None)
    main.handle_retrieve_from_nostr(pm_b)

    labels = [e[1] for e in pm_b.entry_manager.list_entries()]
    assert labels == ["site1"]
