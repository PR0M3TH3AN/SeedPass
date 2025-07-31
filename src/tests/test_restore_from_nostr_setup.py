from pathlib import Path

from helpers import create_vault, dummy_nostr_client, TEST_SEED, TEST_PASSWORD

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


def test_handle_new_seed_setup_restore_from_nostr(monkeypatch, tmp_path, capsys):
    client, _relay = dummy_nostr_client.__wrapped__(tmp_path / "srv", monkeypatch)

    dir_a = tmp_path / "A"
    dir_b = tmp_path / "B"
    dir_a.mkdir()
    dir_b.mkdir()

    pm_src = _init_pm(dir_a, client)
    pm_src.notify = lambda *a, **k: None
    pm_src.entry_manager.add_entry("site1", 12)
    pm_src.sync_vault()

    pm_new = PasswordManager.__new__(PasswordManager)
    pm_new.encryption_mode = EncryptionMode.SEED_ONLY
    pm_new.nostr_client = client
    pm_new.notify = lambda *a, **k: None

    def finalize(seed, *, password=None):
        vault, enc_mgr = create_vault(dir_b, seed, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, dir_b)
        backup_mgr = BackupManager(dir_b, cfg_mgr)
        entry_mgr = EntryManager(vault, backup_mgr)
        pm_new.encryption_manager = enc_mgr
        pm_new.vault = vault
        pm_new.entry_manager = entry_mgr
        pm_new.backup_manager = backup_mgr
        pm_new.config_manager = cfg_mgr
        pm_new.fingerprint_dir = dir_b
        pm_new.current_fingerprint = "fp"
        pm_new.nostr_client = client
        return "fp"

    monkeypatch.setattr(pm_new, "_finalize_existing_seed", finalize)
    monkeypatch.setattr("seedpass.core.manager.masked_input", lambda *_: TEST_SEED)

    inputs = iter(["4"])
    monkeypatch.setattr("builtins.input", lambda *a, **k: next(inputs))

    pm_new.handle_new_seed_setup()
    out = capsys.readouterr().out
    assert "Vault restored from Nostr" in out
    labels = [e[1] for e in pm_new.entry_manager.list_entries()]
    assert labels == ["site1"]
