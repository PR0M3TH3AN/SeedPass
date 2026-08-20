import importlib
from pathlib import Path
from tempfile import TemporaryDirectory
import importlib.util


def test_initialize_profile_creates_directories(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        # Mock home directory so APP_DIR is within tmp_path
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        # Reload constants to use the mocked home directory
        constants = importlib.import_module("constants")
        importlib.reload(constants)
        # Load the script module directly from its path
        script_path = (
            Path(__file__).resolve().parents[2] / "scripts" / "generate_test_profile.py"
        )
        spec = importlib.util.spec_from_file_location(
            "generate_test_profile", script_path
        )
        gtp = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(gtp)

        seed, mgr, dir_path, fingerprint, cfg_mgr = gtp.initialize_profile("test")
        assert cfg_mgr is not None

        # Generated profiles live under APP_DIR/tests so they never mix with
        # real ones. The script used to achieve this by mutating
        # constants.APP_DIR at import time, which leaked into every other
        # importer in the process; it now derives the path per call.
        test_dir = gtp.test_app_dir()
        assert test_dir == constants.APP_DIR / "tests"
        assert test_dir.exists()
        assert (test_dir / "test_seed.txt").exists()
        assert dir_path.parent == test_dir
        assert dir_path.exists()
        assert dir_path.name == fingerprint
