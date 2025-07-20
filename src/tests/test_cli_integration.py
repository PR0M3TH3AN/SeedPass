import importlib
import shutil
from pathlib import Path
from types import SimpleNamespace

from typer.testing import CliRunner

from tests.helpers import TEST_SEED, TEST_PASSWORD

import constants
import seedpass.core.manager as manager_module
import seedpass.cli as cli_module
import utils.password_prompt as pwd_prompt
import colorama


def test_cli_integration(monkeypatch, tmp_path):
    # Redirect home directory so profiles are created under tmp_path
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    importlib.reload(constants)
    importlib.reload(manager_module)
    # Avoid colorama wrapping stdout which breaks CliRunner
    colorama.deinit()
    monkeypatch.setattr(pwd_prompt, "colorama_init", lambda: None)
    importlib.reload(pwd_prompt)
    importlib.reload(cli_module)

    runner = CliRunner()

    # Provide non-interactive responses
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

    # Any unexpected input requests will receive "1" to avoid blocking
    monkeypatch.setattr("builtins.input", lambda *a, **k: "1")

    # Create a profile
    result = runner.invoke(cli_module.app, ["fingerprint", "add"])
    assert result.exit_code == 0

    # Add a password entry
    result = runner.invoke(cli_module.app, ["entry", "add", "Example", "--length", "8"])
    assert result.exit_code == 0
    index = int(result.stdout.strip())

    # Retrieve the entry via search
    result = runner.invoke(cli_module.app, ["entry", "get", "Example"])
    assert result.exit_code == 0
    assert len(result.stdout.strip()) == 8

    # Ensure the index file was created
    fm = manager_module.FingerprintManager(constants.APP_DIR)
    fp = fm.current_fingerprint
    assert fp is not None
    assert (constants.APP_DIR / fp / "seedpass_entries_db.json.enc").exists()

    # Cleanup created data
    shutil.rmtree(constants.APP_DIR, ignore_errors=True)
