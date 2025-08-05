import importlib
import shutil
from pathlib import Path
from types import SimpleNamespace

from tests.helpers import TEST_PASSWORD, TEST_SEED

import colorama
import constants
import seedpass.cli as cli_module
import seedpass.core.manager as manager_module
import utils.password_prompt as pwd_prompt


def test_cli_integration(monkeypatch, tmp_path):
    """Exercise basic CLI flows without interactive prompts."""
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr(colorama, "init", lambda *a, **k: None)
    monkeypatch.setattr(pwd_prompt, "colorama_init", lambda: None)
    importlib.reload(constants)
    importlib.reload(manager_module)
    importlib.reload(pwd_prompt)
    importlib.reload(cli_module)

    # Bypass user prompts and background threads
    monkeypatch.setattr(manager_module, "prompt_seed_words", lambda *a, **k: TEST_SEED)
    monkeypatch.setattr(manager_module, "prompt_new_password", lambda: TEST_PASSWORD)
    monkeypatch.setattr(manager_module, "prompt_for_password", lambda: TEST_PASSWORD)
    monkeypatch.setattr(
        manager_module, "prompt_existing_password", lambda *a, **k: TEST_PASSWORD
    )
    monkeypatch.setattr(manager_module, "confirm_action", lambda *a, **k: True)
    monkeypatch.setattr(manager_module, "masked_input", lambda *_: TEST_SEED)
    monkeypatch.setattr(
        manager_module.PasswordManager, "start_background_sync", lambda *a, **k: None
    )
    monkeypatch.setattr(
        manager_module.PasswordManager,
        "start_background_vault_sync",
        lambda *a, **k: None,
    )
    monkeypatch.setattr(
        manager_module.PasswordManager,
        "start_background_relay_check",
        lambda *a, **k: None,
    )
    monkeypatch.setattr(
        manager_module, "NostrClient", lambda *a, **k: SimpleNamespace()
    )

    def auto_add(self):
        return self.setup_existing_seed(
            method="paste", seed=TEST_SEED, password=TEST_PASSWORD
        )

    monkeypatch.setattr(manager_module.PasswordManager, "add_new_fingerprint", auto_add)
    monkeypatch.setattr("builtins.input", lambda *a, **k: "1")

    cli_module.app(["fingerprint", "add"], standalone_mode=False)

    cli_module.app(["entry", "add", "Example", "--length", "8"], standalone_mode=False)

    cli_module.app(["entry", "get", "Example"], standalone_mode=False)

    fm = manager_module.FingerprintManager(constants.APP_DIR)
    fp = fm.current_fingerprint
    assert fp is not None
    index_file = constants.APP_DIR / fp / "seedpass_entries_db.json.enc"
    assert index_file.exists()

    shutil.rmtree(constants.APP_DIR, ignore_errors=True)
