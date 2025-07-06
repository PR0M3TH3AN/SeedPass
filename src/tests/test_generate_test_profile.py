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

        seed, mgr, dir_path, fingerprint = gtp.initialize_profile("test")

        assert constants.APP_DIR.exists()
        assert (constants.APP_DIR / "test_seed.txt").exists()
        assert dir_path.exists()
        assert dir_path.name == fingerprint
