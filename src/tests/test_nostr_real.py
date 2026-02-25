import os
import sys
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import asyncio
import gzip
import uuid

import pytest
import base64

sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass.core.encryption import EncryptionManager
from seedpass.core.backup import BackupManager
from seedpass.core.config_manager import ConfigManager
from seedpass.core.entry_management import EntryManager
from seedpass.core.manager import EncryptionMode, PasswordManager
from seedpass.core.portable_backup import export_backup, import_backup
from nostr.client import NostrClient
from helpers import create_vault, TEST_SEED, TEST_PASSWORD


@pytest.mark.network
@pytest.mark.skipif(not os.getenv("NOSTR_E2E"), reason="NOSTR_E2E not set")
def test_nostr_publish_and_retrieve():
    seed = (
        "abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon about"
    )
    with TemporaryDirectory() as tmpdir:
        enc_mgr = EncryptionManager(
            base64.urlsafe_b64encode(os.urandom(32)), Path(tmpdir)
        )
        with patch.object(enc_mgr, "decrypt_parent_seed", return_value=seed):
            client = NostrClient(
                enc_mgr,
                f"test_fp_{uuid.uuid4().hex}",
                relays=["wss://relay.snort.social"],
            )
            payload = b"seedpass"
            asyncio.run(client.publish_snapshot(payload))
            time.sleep(2)
            result = asyncio.run(client.fetch_latest_snapshot())
            retrieved = gzip.decompress(b"".join(result[1])) if result else None
            client.close_client_pool()
            assert retrieved == payload


def _relays_from_env() -> list[str]:
    raw = os.getenv("NOSTR_RELAYS", "")
    relays = [value.strip() for value in raw.split(",") if value.strip()]
    return relays or ["wss://relay.snort.social"]


def _init_pm_for_real_nostr(dir_path: Path, client: NostrClient) -> PasswordManager:
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
    pm.parent_seed = TEST_SEED
    pm.is_dirty = False
    pm.secret_mode_enabled = False
    pm.state_manager = None
    pm.offline_mode = False
    pm.notify = lambda *a, **k: None
    return pm


@pytest.mark.network
@pytest.mark.skipif(not os.getenv("NOSTR_E2E"), reason="NOSTR_E2E not set")
def test_account_roundtrip_sync_delete_restore_real_relays():
    """Real relay roundtrip:
    create account -> add entries -> sync -> delete local -> restore by seed.
    """
    relays = _relays_from_env()
    account_index = int(uuid.uuid4().int % (2**31 - 1))
    fingerprint = f"test_fp_{uuid.uuid4().hex}"

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        source_dir = root / "source"
        restore_dir = root / "restore"
        source_dir.mkdir()
        restore_dir.mkdir()

        _, source_enc = create_vault(source_dir, TEST_SEED, TEST_PASSWORD)
        source_client = NostrClient(
            source_enc,
            fingerprint,
            relays=relays,
            parent_seed=TEST_SEED,
            account_index=account_index,
        )
        pm_source = _init_pm_for_real_nostr(source_dir, source_client)
        pm_source.entry_manager.add_entry(
            "roundtrip-site", 15, username="alice", url="https://example.com"
        )
        pm_source.entry_manager.add_totp(
            "roundtrip-totp",
            TEST_SEED,
            deterministic=True,
            period=45,
            digits=8,
        )
        pm_source.entry_manager.add_key_value("roundtrip-kv", "token", "abc123")

        sync = pm_source.sync_vault()
        assert sync is not None

        index_file = source_dir / "seedpass_entries_db.json.enc"
        if index_file.exists():
            index_file.unlink()
        assert not index_file.exists()

        restore_vault, restore_enc = create_vault(restore_dir, TEST_SEED, TEST_PASSWORD)
        restore_client = NostrClient(
            restore_enc,
            fingerprint,
            relays=relays,
            parent_seed=TEST_SEED,
            account_index=account_index,
        )
        pm_restore = _init_pm_for_real_nostr(restore_dir, restore_client)

        restored = False
        for attempt in range(6):
            restored = pm_restore.attempt_initial_sync()
            if restored:
                break
            time.sleep(1.5 * (attempt + 1))
        assert restored is True

        pm_restore.entry_manager.clear_cache()
        labels = [item[1] for item in pm_restore.entry_manager.list_entries(verbose=False)]
        assert sorted(labels) == ["roundtrip-kv", "roundtrip-site", "roundtrip-totp"]

        pw = pm_restore.entry_manager.retrieve_entry(0)
        totp = pm_restore.entry_manager.retrieve_entry(1)
        kv = pm_restore.entry_manager.retrieve_entry(2)
        assert pw and pw["kind"] == "password" and pw["username"] == "alice"
        assert totp and totp["kind"] == "totp" and totp["deterministic"] is True
        assert kv and kv["kind"] == "key_value" and kv["value"] == "abc123"

        source_client.close_client_pool()
        restore_client.close_client_pool()


@pytest.mark.network
@pytest.mark.skipif(not os.getenv("NOSTR_E2E"), reason="NOSTR_E2E not set")
def test_real_relays_with_portable_export_import_roundtrip():
    """Live relay + portable backup chain in one E2E flow."""
    relays = _relays_from_env()
    account_index = int(uuid.uuid4().int % (2**31 - 1))
    fingerprint = f"test_fp_{uuid.uuid4().hex}"

    with TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        source_dir = root / "source"
        import_dir = root / "imported"
        relay_restore_dir = root / "relay-restore"
        source_dir.mkdir()
        import_dir.mkdir()
        relay_restore_dir.mkdir()

        source_vault, source_enc = create_vault(source_dir, TEST_SEED, TEST_PASSWORD)
        source_client = NostrClient(
            source_enc,
            fingerprint,
            relays=relays,
            parent_seed=TEST_SEED,
            account_index=account_index,
        )
        pm_source = _init_pm_for_real_nostr(source_dir, source_client)

        pm_source.entry_manager.add_entry(
            "portable-site", 18, username="carol", url="https://portable.example"
        )
        pm_source.entry_manager.add_totp(
            "portable-totp",
            TEST_SEED,
            deterministic=True,
            period=30,
            digits=6,
        )
        pm_source.entry_manager.add_key_value("portable-kv", "api", "xyz789")

        first_sync = pm_source.sync_vault()
        assert first_sync is not None

        export_path = root / "portable-export.json"
        path = export_backup(
            pm_source.vault,
            pm_source.backup_manager,
            dest_path=export_path,
            parent_seed=TEST_SEED,
            encrypt=True,
        )
        assert path.exists()

        _, import_enc = create_vault(import_dir, TEST_SEED, TEST_PASSWORD)
        import_client = NostrClient(
            import_enc,
            fingerprint,
            relays=relays,
            parent_seed=TEST_SEED,
            account_index=account_index,
        )
        pm_import = _init_pm_for_real_nostr(import_dir, import_client)
        import_backup(
            pm_import.vault,
            pm_import.backup_manager,
            path,
            parent_seed=TEST_SEED,
        )
        pm_import.entry_manager.clear_cache()

        imported_labels = [
            item[1] for item in pm_import.entry_manager.list_entries(verbose=False)
        ]
        assert sorted(imported_labels) == ["portable-kv", "portable-site", "portable-totp"]

        resync = pm_import.sync_vault()
        assert resync is not None

        _, relay_enc = create_vault(relay_restore_dir, TEST_SEED, TEST_PASSWORD)
        relay_client = NostrClient(
            relay_enc,
            fingerprint,
            relays=relays,
            parent_seed=TEST_SEED,
            account_index=account_index,
        )
        pm_relay_restore = _init_pm_for_real_nostr(relay_restore_dir, relay_client)

        restored = False
        for attempt in range(6):
            restored = pm_relay_restore.attempt_initial_sync()
            if restored:
                break
            time.sleep(1.5 * (attempt + 1))
        assert restored is True

        pm_relay_restore.entry_manager.clear_cache()
        relay_labels = [
            item[1] for item in pm_relay_restore.entry_manager.list_entries(verbose=False)
        ]
        assert sorted(relay_labels) == ["portable-kv", "portable-site", "portable-totp"]

        source_client.close_client_pool()
        import_client.close_client_pool()
        relay_client.close_client_pool()
