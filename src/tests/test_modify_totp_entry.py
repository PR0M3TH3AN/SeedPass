from helpers import create_vault, TEST_SEED, TEST_PASSWORD
import pytest

from password_manager.entry_management import EntryManager
from password_manager.backup import BackupManager
from password_manager.config_manager import ConfigManager


def test_modify_totp_entry_period_digits_and_archive(tmp_path):
    vault, _ = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    cfg_mgr = ConfigManager(vault, tmp_path)
    backup_mgr = BackupManager(tmp_path, cfg_mgr)
    em = EntryManager(vault, backup_mgr)

    em.add_totp("Example", TEST_SEED, period=30, digits=6)
    em.modify_entry(0, period=60, digits=8, archived=True)

    entry = em.retrieve_entry(0)
    assert entry["period"] == 60
    assert entry["digits"] == 8
    assert entry["archived"] is True


def test_modify_totp_entry_invalid_field(tmp_path):
    vault, _ = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    cfg_mgr = ConfigManager(vault, tmp_path)
    backup_mgr = BackupManager(tmp_path, cfg_mgr)
    em = EntryManager(vault, backup_mgr)

    em.add_totp("Example", TEST_SEED)
    with pytest.raises(ValueError):
        em.modify_entry(0, username="alice")
