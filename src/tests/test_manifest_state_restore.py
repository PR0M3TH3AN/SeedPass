import asyncio
from pathlib import Path
from tempfile import TemporaryDirectory

from helpers import create_vault, TEST_SEED

from seedpass.core.entry_management import EntryManager
from seedpass.core.backup import BackupManager
from seedpass.core.config_manager import ConfigManager
from seedpass.core.state_manager import StateManager
from seedpass.core.manager import PasswordManager, EncryptionMode


def _init_pm(dir_path: Path, client) -> PasswordManager:
    vault, enc_mgr = create_vault(dir_path)
    cfg_mgr = ConfigManager(vault, dir_path)
    backup_mgr = BackupManager(dir_path, cfg_mgr)
    entry_mgr = EntryManager(vault, backup_mgr)
    state_mgr = StateManager(dir_path)

    pm = PasswordManager.__new__(PasswordManager)
    pm.encryption_mode = EncryptionMode.SEED_ONLY
    pm.encryption_manager = enc_mgr
    pm.vault = vault
    pm.entry_manager = entry_mgr
    pm.backup_manager = backup_mgr
    pm.config_manager = cfg_mgr
    pm.state_manager = state_mgr
    pm.nostr_client = client
    pm.fingerprint_dir = dir_path
    pm.current_fingerprint = "fp"
    pm.parent_seed = TEST_SEED
    pm.is_dirty = False
    return pm


def test_manifest_state_restored(monkeypatch, tmp_path, make_dummy_nostr_client):
    client, relay = make_dummy_nostr_client(tmp_path / "c1")
    with TemporaryDirectory() as tmpdir:
        fp_dir = Path(tmpdir)
        pm1 = _init_pm(fp_dir, client)
        pm1.entry_manager.add_entry("site", 8)
        result = pm1.sync_vault()
        manifest_id = relay.manifests[-1].tags[0]
        state = pm1.state_manager.state
        delta_ts = state["delta_since"]
        assert state["manifest_id"] == manifest_id
        assert delta_ts > 0
        assert result["manifest_id"] == manifest_id

        client2, _ = make_dummy_nostr_client(tmp_path / "c2")
        monkeypatch.setattr(
            "seedpass.core.manager.NostrClient", lambda *a, **k: client2
        )

        pm2 = PasswordManager.__new__(PasswordManager)
        pm2.encryption_mode = EncryptionMode.SEED_ONLY
        vault2, enc_mgr2 = create_vault(fp_dir)
        pm2.encryption_manager = enc_mgr2
        pm2.vault = vault2
        pm2.fingerprint_dir = fp_dir
        pm2.current_fingerprint = "fp"
        pm2.parent_seed = TEST_SEED
        pm2.bip85 = None
        pm2.initialize_managers()

        assert pm2.nostr_client is client2
        assert pm2.nostr_client.get_current_manifest_id() == manifest_id
        assert pm2.nostr_client.get_current_manifest().delta_since == delta_ts
        assert pm2.last_sync_ts == delta_ts
