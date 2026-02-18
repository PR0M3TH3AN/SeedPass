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


def test_full_sync_roundtrip(dummy_nostr_client):
    client, relay = dummy_nostr_client
    with TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        dir_a = base / "A"
        dir_b = base / "B"
        dir_a.mkdir()
        dir_b.mkdir()

        pm_a = _init_pm(dir_a, client)
        pm_b = _init_pm(dir_b, client)

        # Manager A publishes initial snapshot
        pm_a.entry_manager.add_entry("site1", 12)
        pm_a.sync_vault()
        manifest_id = relay.manifests[-1].tags[0]

        # Manager B retrieves snapshot
        result = pm_b.attempt_initial_sync()
        assert result is True
        entries = pm_b.entry_manager.list_entries()
        assert [e[1] for e in entries] == ["site1"]

        # Manager A publishes delta with second entry
        pm_a.entry_manager.add_entry("site2", 12)
        delta_bytes = pm_a.vault.get_encrypted_index() or b""
        asyncio.run(client.publish_delta(delta_bytes, manifest_id))
        delta_ts = relay.deltas[-1].created_at
        assert relay.manifests[-1].delta_since == delta_ts

        # Manager B fetches delta and updates
        pm_b.sync_index_from_nostr()
        pm_b.entry_manager.clear_cache()
        labels = [e[1] for e in pm_b.entry_manager.list_entries()]
        assert sorted(labels) == ["site1", "site2"]
