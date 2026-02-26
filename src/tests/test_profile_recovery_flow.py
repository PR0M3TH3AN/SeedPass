from pathlib import Path
from types import SimpleNamespace

import seedpass.core.manager as manager_module
from helpers import TEST_SEED
from utils.fingerprint import generate_fingerprint


def test_add_new_fingerprint_switch_existing_selects_profile(monkeypatch, tmp_path):
    pm = manager_module.PasswordManager.__new__(manager_module.PasswordManager)
    fingerprint = generate_fingerprint(TEST_SEED)
    pm.fingerprint_manager = SimpleNamespace(
        current_fingerprint=None,
        select_fingerprint=lambda fp: True,
    )
    pm.config_manager = None
    pm.encryption_manager = None

    monkeypatch.setattr(
        manager_module.PasswordManager,
        "setup_existing_seed",
        lambda self, *a, **k: fingerprint,
    )
    monkeypatch.setattr("builtins.input", lambda *_a, **_k: "1")

    called = {}

    def fake_select(self, fp, password=None):
        called["fp"] = fp
        self.encryption_manager = object()
        return True

    monkeypatch.setattr(
        manager_module.PasswordManager, "select_fingerprint", fake_select
    )

    result = pm.add_new_fingerprint()

    assert result == fingerprint
    assert called["fp"] == fingerprint


def test_select_fingerprint_returns_false_on_unlock_failure(monkeypatch, tmp_path):
    pm = manager_module.PasswordManager.__new__(manager_module.PasswordManager)
    fingerprint = "ABCDEF1234567890"
    fingerprint_dir = Path(tmp_path) / fingerprint
    fingerprint_dir.mkdir(parents=True, exist_ok=True)

    pm.fingerprint_manager = SimpleNamespace(
        select_fingerprint=lambda fp: fp == fingerprint,
        get_current_fingerprint_dir=lambda: fingerprint_dir,
    )

    monkeypatch.setattr(
        manager_module.PasswordManager,
        "setup_encryption_manager",
        lambda self, *a, **k: False,
    )

    assert pm.select_fingerprint(fingerprint) is False


def test_recover_profile_with_blank_index_rejects_mismatched_seed(
    monkeypatch, tmp_path
):
    pm = manager_module.PasswordManager.__new__(manager_module.PasswordManager)
    existing_seed = TEST_SEED
    existing_fp = generate_fingerprint(existing_seed)
    other_seed = (
        "legal winner thank year wave sausage worth useful legal winner thank yellow"
    )
    profile_dir = Path(tmp_path) / existing_fp
    profile_dir.mkdir(parents=True, exist_ok=True)

    pm.fingerprint_manager = SimpleNamespace(
        list_fingerprints=lambda: [existing_fp],
        display_name=lambda fp: fp,
        get_fingerprint_directory=lambda fp: profile_dir if fp == existing_fp else None,
        current_fingerprint=None,
    )
    pm.validate_bip85_seed = lambda seed: True

    inputs = iter(["1", "1"])
    monkeypatch.setattr("builtins.input", lambda *_a, **_k: next(inputs))
    monkeypatch.setattr(manager_module, "masked_input", lambda *_a, **_k: other_seed)
    monkeypatch.setattr(manager_module, "confirm_action", lambda *_a, **_k: True)

    assert pm.recover_profile_with_blank_index() is False
