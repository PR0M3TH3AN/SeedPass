from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from seedpass.core.manager import PasswordManager
from seedpass.core.config_manager import ConfigManager
from seedpass.core.errors import SeedPassError
from helpers import create_vault, TEST_SEED, TEST_PASSWORD


def test_invalid_password_shows_friendly_message_once(capsys):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        vault, _ = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
        pm = PasswordManager.__new__(PasswordManager)
        pm.config_manager = ConfigManager(vault, tmp_path)
        pm.fingerprint_dir = tmp_path
        pm.parent_seed = ""
        with pytest.raises(SeedPassError):
            pm.load_parent_seed(tmp_path, password="wrongpass")
        captured = capsys.readouterr().out
        assert captured.count("Incorrect password or corrupt file") == 1
