import asyncio
from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import create_vault

from seedpass.core.entry_management import EntryManager
from seedpass.core.backup import BackupManager
from seedpass.core.config_manager import ConfigManager
from seedpass.core.manager import PasswordManager, EncryptionMode


def _init_pm(dir_path: Path, client) -> PasswordManager:
    vault, enc_mgr = create_vault(dir_path)
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
    pm.is_dirty = False
    return pm


def test_sync_applies_multiple_deltas(dummy_nostr_client):
    client, relay = dummy_nostr_client
    with TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        dir_a = base / "A"
        dir_b = base / "B"
        dir_a.mkdir()
        dir_b.mkdir()

        pm_a = _init_pm(dir_a, client)
        pm_b = _init_pm(dir_b, client)

        # Initial snapshot from manager A
        pm_a.entry_manager.add_entry("site1", 12)
        pm_a.sync_vault()
        manifest_id = relay.manifests[-1].tags[0]

        # Manager B downloads snapshot
        assert pm_b.attempt_initial_sync() is True

        # Two deltas published sequentially
        pm_a.entry_manager.add_entry("site2", 12)
        delta1 = pm_a.vault.get_encrypted_index() or b""
        asyncio.run(client.publish_delta(delta1, manifest_id))

        pm_a.entry_manager.add_entry("site3", 12)
        delta2 = pm_a.vault.get_encrypted_index() or b""
        asyncio.run(client.publish_delta(delta2, manifest_id))

        # B syncs and should apply both deltas
        pm_b.sync_index_from_nostr()
        pm_b.entry_manager.clear_cache()
        labels = [e[1] for e in pm_b.entry_manager.list_entries()]
        assert sorted(labels) == ["site1", "site2", "site3"]


def test_initial_sync_applies_multiple_deltas(dummy_nostr_client):
    client, relay = dummy_nostr_client
    with TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        dir_a = base / "A"
        dir_b = base / "B"
        dir_a.mkdir()
        dir_b.mkdir()

        pm_a = _init_pm(dir_a, client)
        pm_b = _init_pm(dir_b, client)

        pm_a.entry_manager.add_entry("site1", 12)
        pm_a.sync_vault()
        manifest_id = relay.manifests[-1].tags[0]

        pm_a.entry_manager.add_entry("site2", 12)
        delta1 = pm_a.vault.get_encrypted_index() or b""
        asyncio.run(client.publish_delta(delta1, manifest_id))

        pm_a.entry_manager.add_entry("site3", 12)
        delta2 = pm_a.vault.get_encrypted_index() or b""
        asyncio.run(client.publish_delta(delta2, manifest_id))

        # Initial sync after both deltas published
        assert pm_b.attempt_initial_sync() is True
        pm_b.entry_manager.clear_cache()
        labels = [e[1] for e in pm_b.entry_manager.list_entries()]
        assert sorted(labels) == ["site1", "site2", "site3"]
