from __future__ import annotations

import shutil
from pathlib import Path

from helpers import TEST_PASSWORD, TEST_SEED, create_vault
from seedpass.core.backup import BackupManager
from seedpass.core.config_manager import ConfigManager
from seedpass.core.entry_management import EntryManager
from seedpass.core.manager import EncryptionMode, PasswordManager
from seedpass.core.portable_backup import export_backup, import_backup


def _init_pm(dir_path: Path, nostr_client=None) -> PasswordManager:
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
    pm.nostr_client = nostr_client
    pm.fingerprint_dir = dir_path
    pm.current_fingerprint = "fp"
    pm.parent_seed = TEST_SEED
    pm.is_dirty = False
    pm.secret_mode_enabled = False
    pm.state_manager = None
    pm.offline_mode = False
    pm.notify = lambda *a, **k: None
    return pm


def _add_sample_entries(entry_mgr: EntryManager) -> None:
    entry_mgr.add_entry(
        "example.com",
        14,
        username="alice",
        url="https://example.com",
        notes="password note",
        tags=["web"],
    )
    entry_mgr.add_totp(
        "example-totp",
        TEST_SEED,
        deterministic=True,
        period=45,
        digits=8,
        notes="totp note",
        tags=["otp"],
    )
    entry_mgr.add_key_value(
        "api-token",
        "token",
        "abc123",
        notes="kv note",
        tags=["api"],
    )


def _assert_sample_entries(entry_mgr: EntryManager) -> None:
    pw = entry_mgr.retrieve_entry(0)
    totp = entry_mgr.retrieve_entry(1)
    kv = entry_mgr.retrieve_entry(2)

    assert pw is not None
    assert pw["kind"] == "password"
    assert pw["label"] == "example.com"
    assert pw["username"] == "alice"
    assert pw["url"] == "https://example.com"
    assert pw["length"] == 14
    assert pw["notes"] == "password note"

    assert totp is not None
    assert totp["kind"] == "totp"
    assert totp["label"] == "example-totp"
    assert totp["deterministic"] is True
    assert totp["index"] == 0
    assert totp["period"] == 45
    assert totp["digits"] == 8
    assert totp["notes"] == "totp note"

    assert kv is not None
    assert kv["kind"] == "key_value"
    assert kv["label"] == "api-token"
    assert kv["key"] == "token"
    assert kv["value"] == "abc123"
    assert kv["notes"] == "kv note"

    labels = [item[1] for item in entry_mgr.list_entries(verbose=False)]
    assert labels == ["example.com", "example-totp", "api-token"]


def test_account_roundtrip_via_nostr_seed_restore(tmp_path, make_dummy_nostr_client):
    client, relay = make_dummy_nostr_client(tmp_path / "relay")

    source_dir = tmp_path / "account-source"
    source_dir.mkdir()
    pm_source = _init_pm(source_dir, client)
    _add_sample_entries(pm_source.entry_manager)

    sync_result = pm_source.sync_vault()
    assert sync_result is not None
    assert relay.manifests

    shutil.rmtree(source_dir)
    assert not source_dir.exists()

    restored_dir = tmp_path / "account-restored"
    restored_dir.mkdir()
    pm_restored = _init_pm(restored_dir, client)

    restored = pm_restored.attempt_initial_sync()
    assert restored is True
    pm_restored.entry_manager.clear_cache()
    _assert_sample_entries(pm_restored.entry_manager)


def test_account_roundtrip_via_export_import_seed_restore(tmp_path):
    source_dir = tmp_path / "account-source"
    source_dir.mkdir()
    pm_source = _init_pm(source_dir, None)
    _add_sample_entries(pm_source.entry_manager)

    export_path = tmp_path / "seedpass-portable-export.json"
    path = export_backup(
        pm_source.vault,
        pm_source.backup_manager,
        dest_path=export_path,
        parent_seed=TEST_SEED,
        encrypt=True,
    )
    assert path.exists()

    shutil.rmtree(source_dir)
    assert not source_dir.exists()

    restored_dir = tmp_path / "account-restored"
    restored_dir.mkdir()
    pm_restored = _init_pm(restored_dir, None)

    import_backup(
        pm_restored.vault,
        pm_restored.backup_manager,
        path,
        parent_seed=TEST_SEED,
    )
    pm_restored.entry_manager.clear_cache()
    _assert_sample_entries(pm_restored.entry_manager)
