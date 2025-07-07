import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import pytest

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.entry_management import EntryManager
from password_manager.backup import BackupManager
from password_manager.vault import Vault
from password_manager.config_manager import ConfigManager
from password_manager.totp import TotpManager
import pyotp


def test_add_totp_and_get_code():
    with TemporaryDirectory() as tmpdir:
        vault, enc_mgr = create_vault(Path(tmpdir), TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, Path(tmpdir))
        backup_mgr = BackupManager(Path(tmpdir), cfg_mgr)
        entry_mgr = EntryManager(vault, backup_mgr)

        uri = entry_mgr.add_totp("Example", TEST_SEED)
        assert uri.startswith("otpauth://totp/")

        entry = entry_mgr.retrieve_entry(0)
        assert entry == {
            "type": "totp",
            "kind": "totp",
            "label": "Example",
            "index": 0,
            "period": 30,
            "digits": 6,
            "archived": False,
            "notes": "",
        }

        code = entry_mgr.get_totp_code(0, TEST_SEED, timestamp=0)

        expected = TotpManager.current_code(TEST_SEED, 0, timestamp=0)
        assert code == expected


def test_totp_time_remaining(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        vault, enc_mgr = create_vault(Path(tmpdir), TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, Path(tmpdir))
        backup_mgr = BackupManager(Path(tmpdir), cfg_mgr)
        entry_mgr = EntryManager(vault, backup_mgr)

        entry_mgr.add_totp("Example", TEST_SEED)

        monkeypatch.setattr(TotpManager, "time_remaining", lambda period: 7)
        remaining = entry_mgr.get_totp_time_remaining(0)
        assert remaining == 7


def test_add_totp_imported(tmp_path):
    vault, enc = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    cfg_mgr = ConfigManager(vault, tmp_path)
    backup_mgr = BackupManager(tmp_path, cfg_mgr)
    em = EntryManager(vault, backup_mgr)
    secret = "JBSWY3DPEHPK3PXP"
    em.add_totp("Imported", TEST_SEED, secret=secret)
    entry = em.retrieve_entry(0)
    assert entry == {
        "type": "totp",
        "kind": "totp",
        "label": "Imported",
        "secret": secret,
        "period": 30,
        "digits": 6,
        "archived": False,
        "notes": "",
    }
    code = em.get_totp_code(0, timestamp=0)
    assert code == pyotp.TOTP(secret).at(0)


def test_add_totp_with_notes(tmp_path):
    vault, _ = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    cfg_mgr = ConfigManager(vault, tmp_path)
    backup_mgr = BackupManager(tmp_path, cfg_mgr)
    em = EntryManager(vault, backup_mgr)

    em.add_totp("NoteLabel", TEST_SEED, notes="some note")
    entry = em.retrieve_entry(0)
    assert entry["notes"] == "some note"
