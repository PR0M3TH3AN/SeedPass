import sys
import importlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import pytest
from unittest.mock import patch

sys.path.append(str(Path(__file__).resolve().parents[1]))


def setup_pm(tmp_path):
    import constants
    import seedpass.core.manager as manager_module

    importlib.reload(constants)
    importlib.reload(manager_module)

    pm = manager_module.PasswordManager.__new__(manager_module.PasswordManager)
    pm.encryption_mode = manager_module.EncryptionMode.SEED_ONLY
    pm.fingerprint_manager = manager_module.FingerprintManager(constants.APP_DIR)
    pm.current_fingerprint = None
    return pm, constants, manager_module


def test_generate_seed_cleanup_on_failure(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        pm, const, mgr = setup_pm(tmp_path)

        with patch("seedpass.core.manager.confirm_action", return_value=True):
            monkeypatch.setattr(
                pm,
                "save_and_encrypt_seed",
                lambda seed, d: (_ for _ in ()).throw(RuntimeError("fail")),
            )
            with pytest.raises(RuntimeError):
                pm.generate_new_seed()

        # fingerprint list should be empty and only fingerprints.json should remain
        assert pm.fingerprint_manager.list_fingerprints() == []
        contents = list(const.APP_DIR.iterdir())
        assert len(contents) == 1 and contents[0].name == "fingerprints.json"
        fp_file = pm.fingerprint_manager.fingerprints_file
        with open(fp_file) as f:
            data = json.load(f)
        assert data.get("fingerprints") == []
