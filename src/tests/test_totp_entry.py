import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import pytest

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass.core.entry_management import EntryManager
from seedpass.core.backup import BackupManager
from seedpass.core.vault import Vault
from seedpass.core.config_manager import ConfigManager
from seedpass.core.totp import TotpManager
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
        assert entry["deterministic"] is False
        assert "secret" in entry

        code = entry_mgr.get_totp_code(0, timestamp=0)

        expected = pyotp.TOTP(entry["secret"]).at(0)
        assert code == expected

        # second entry should have different secret
        entry_mgr.add_totp("Other", TEST_SEED)
        entry2 = entry_mgr.retrieve_entry(1)
        assert entry["secret"] != entry2["secret"]


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
    assert entry["secret"] == secret
    assert entry["deterministic"] is False
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


def test_legacy_deterministic_entry(tmp_path):
    vault, enc = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    cfg_mgr = ConfigManager(vault, tmp_path)
    backup_mgr = BackupManager(tmp_path, cfg_mgr)
    em = EntryManager(vault, backup_mgr)

    em.add_totp("Legacy", TEST_SEED, deterministic=True)
    data = em._load_index()
    entry = data["entries"]["0"]
    entry.pop("deterministic", None)
    em._save_index(data)

    code = em.get_totp_code(0, TEST_SEED, timestamp=0)
    expected = TotpManager.current_code(TEST_SEED, 0, timestamp=0)
    assert code == expected

    exported = em.export_totp_entries(TEST_SEED)
    assert exported["entries"][0]["secret"] == TotpManager.derive_secret(TEST_SEED, 0)


def test_totp_code_honors_entry_period_and_digits(tmp_path):
    """An entry's recorded period/digits govern its code.

    Regression: codes were generated with pyotp's defaults (6 digits, 30s)
    regardless of what the entry recorded, so any imported 8-digit or
    45-second secret produced codes the issuing service rejects. Found by
    scripts/cross_impl_check.py comparing against the TypeScript port.
    """
    import pyotp

    from helpers import TEST_PASSWORD, TEST_SEED, create_vault
    from seedpass.core.backup import BackupManager
    from seedpass.core.config_manager import ConfigManager
    from seedpass.core.entry_management import EntryManager

    vault, _enc = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    cfg = ConfigManager(vault, tmp_path)
    entry_mgr = EntryManager(vault, BackupManager(tmp_path, cfg))

    secret = "JBSWY3DPEHPK3PXP"
    timestamp = 1700000000

    idx = entry_mgr.get_next_index()
    entry_mgr.add_totp("custom", secret=secret, period=45, digits=8)
    code = entry_mgr.get_totp_code(idx, timestamp=timestamp)
    expected = pyotp.TOTP(secret, interval=45, digits=8).at(timestamp)
    assert code == expected
    assert len(code) == 8

    # Defaults still behave exactly as before
    idx_default = entry_mgr.get_next_index()
    entry_mgr.add_totp("plain", secret=secret)
    default_code = entry_mgr.get_totp_code(idx_default, timestamp=timestamp)
    assert default_code == pyotp.TOTP(secret).at(timestamp)
    assert len(default_code) == 6


def test_deterministic_totp_code_honors_entry_period_and_digits(tmp_path):
    """The same rule applies to derived (deterministic) TOTP entries."""
    import pyotp

    from helpers import TEST_PASSWORD, TEST_SEED, create_vault
    from seedpass.core.backup import BackupManager
    from seedpass.core.config_manager import ConfigManager
    from seedpass.core.entry_management import EntryManager
    from seedpass.core.totp import TotpManager

    vault, _enc = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    cfg = ConfigManager(vault, tmp_path)
    entry_mgr = EntryManager(vault, BackupManager(tmp_path, cfg))

    idx = entry_mgr.get_next_index()
    entry_mgr.add_totp("derived", TEST_SEED, deterministic=True, period=60, digits=8)
    timestamp = 1700000000
    code = entry_mgr.get_totp_code(idx, TEST_SEED, timestamp=timestamp)
    derived_secret = TotpManager.derive_secret(TEST_SEED, 0)
    assert code == pyotp.TOTP(derived_secret, interval=60, digits=8).at(timestamp)
    assert len(code) == 8
