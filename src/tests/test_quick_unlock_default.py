import logging
from types import SimpleNamespace
from pathlib import Path
import sys

import pytest

sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass.core.manager import PasswordManager
from seedpass.core.config_manager import ConfigManager
from helpers import create_vault, TEST_SEED, TEST_PASSWORD


def test_quick_unlock_default_off(tmp_path):
    vault, _ = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    cfg_mgr = ConfigManager(vault, tmp_path)
    assert cfg_mgr.get_quick_unlock() is False


def test_quick_unlock_logs_event(tmp_path, caplog):
    pm = PasswordManager.__new__(PasswordManager)
    pm.fingerprint_dir = tmp_path
    pm.current_fingerprint = "user123"
    pm.setup_encryption_manager = lambda *a, **k: None
    pm.initialize_bip85 = lambda: None
    pm.initialize_managers = lambda: None
    pm.update_activity = lambda: None
    pm.config_manager = SimpleNamespace(get_quick_unlock=lambda: True)

    with caplog.at_level(logging.INFO):
        pm.unlock_vault(password="pw")

    assert any("Quick unlock used by user123" in rec.message for rec in caplog.records)
