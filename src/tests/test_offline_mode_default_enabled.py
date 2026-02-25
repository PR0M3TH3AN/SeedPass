from pathlib import Path
from tempfile import TemporaryDirectory

from seedpass.core.config_manager import ConfigManager
from helpers import create_vault, TEST_SEED, TEST_PASSWORD


def test_offline_mode_default_enabled():
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        vault, enc_mgr = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, tmp_path)
        config = cfg_mgr.load_config(require_pin=False)
        assert config["offline_mode"] is True
