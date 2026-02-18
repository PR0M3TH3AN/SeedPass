import asyncio
import threading
from pathlib import Path


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
    pm.state_manager = None
    return pm


def test_sync_race_conditions(monkeypatch, tmp_path, make_dummy_nostr_client):
    client_a, relay = make_dummy_nostr_client(tmp_path / "c1")

    from cryptography.fernet import Fernet
    from nostr.client import NostrClient
    from seedpass.core.encryption import EncryptionManager
    from helpers import TEST_SEED

    enc_mgr = EncryptionManager(Fernet.generate_key(), tmp_path / "c2")

    class DummyKeys:
        def private_key_hex(self):
            return "1" * 64

        def public_key_hex(self):
            return "2" * 64

    class DummyKeyManager:
        def __init__(self, *a, **k):
            self.keys = DummyKeys()

    monkeypatch.setattr("nostr.client.KeyManager", DummyKeyManager)
    monkeypatch.setattr(enc_mgr, "decrypt_parent_seed", lambda: TEST_SEED)
    client_b = NostrClient(enc_mgr, "fp")

    dir_a = tmp_path / "A"
    dir_b = tmp_path / "B"
    dir_a.mkdir()
    dir_b.mkdir()

    pm_a = _init_pm(dir_a, client_a)
    pm_b = _init_pm(dir_b, client_b)

    pm_a.entry_manager.add_entry("init", 12)
    pm_a.sync_vault()
    manifest_id = relay.manifests[-1].tags[0]
    assert pm_b.attempt_initial_sync() is True

    pm_b.entry_manager.get_next_index = lambda: 2

    def publish(pm: PasswordManager, client, label: str) -> None:
        pm.entry_manager.add_entry(label, 12)
        data = pm.vault.get_encrypted_index() or b""
        try:
            asyncio.run(client.publish_delta(data, manifest_id))
        except RuntimeError:
            pm.sync_index_from_nostr()
            pm.entry_manager.clear_cache()
            pm.entry_manager.add_entry(label, 12)
            data = pm.vault.get_encrypted_index() or b""
            asyncio.run(client.publish_delta(data, manifest_id))

    t1 = threading.Thread(target=publish, args=(pm_a, client_a, "from_a"))
    t2 = threading.Thread(target=publish, args=(pm_b, client_b, "from_b"))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert len(relay.deltas) >= 1

    pm_b.sync_index_from_nostr()
    pm_b.entry_manager.clear_cache()
    labels = [e[1] for e in pm_b.entry_manager.list_entries()]
    assert "from_a" in labels and "from_b" in labels
