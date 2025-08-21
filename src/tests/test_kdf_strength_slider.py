from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from helpers import create_vault, TEST_SEED, TEST_PASSWORD
from seedpass.core.config_manager import ConfigManager
from main import handle_set_kdf_iterations


def test_kdf_strength_slider_persists(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        vault, enc_mgr = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
        cfg_mgr = ConfigManager(vault, tmp_path)
        pm = SimpleNamespace(config_manager=cfg_mgr)
        inputs = iter(["3"])
        monkeypatch.setattr("builtins.input", lambda *_: next(inputs))
        handle_set_kdf_iterations(pm)
        assert cfg_mgr.get_kdf_iterations() == 100_000
