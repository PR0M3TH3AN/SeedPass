import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import pytest

from helpers import create_vault, TEST_SEED, TEST_PASSWORD

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.entry_management import EntryManager
from password_manager.vault import Vault
from password_manager.totp import TotpManager


def test_add_totp_and_get_code():
    with TemporaryDirectory() as tmpdir:
        vault, enc_mgr = create_vault(Path(tmpdir), TEST_SEED, TEST_PASSWORD)
        entry_mgr = EntryManager(vault, Path(tmpdir))

        uri = entry_mgr.add_totp("Example", TEST_SEED)
        assert uri.startswith("otpauth://totp/")

        entry = entry_mgr.retrieve_entry(0)
        assert entry == {
            "type": "totp",
            "label": "Example",
            "index": 0,
            "period": 30,
            "digits": 6,
        }

        code = entry_mgr.get_totp_code(0, TEST_SEED, timestamp=0)

        expected = TotpManager.current_code(TEST_SEED, 0, timestamp=0)
        assert code == expected


def test_totp_time_remaining(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        vault, enc_mgr = create_vault(Path(tmpdir), TEST_SEED, TEST_PASSWORD)
        entry_mgr = EntryManager(vault, Path(tmpdir))

        entry_mgr.add_totp("Example", TEST_SEED)

        monkeypatch.setattr(TotpManager, "time_remaining", lambda period: 7)
        remaining = entry_mgr.get_totp_time_remaining(0)
        assert remaining == 7
