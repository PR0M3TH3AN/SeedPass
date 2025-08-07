import builtins
from types import SimpleNamespace

import seedpass.core.manager as manager_module
from helpers import TEST_SEED


def test_add_new_fingerprint_word_entry_exits(monkeypatch):
    pm = manager_module.PasswordManager.__new__(manager_module.PasswordManager)
    pm.fingerprint_manager = SimpleNamespace(current_fingerprint=None)
    pm.initialize_managers = lambda: None

    calls = {"count": 0}
    original_setup = manager_module.PasswordManager.setup_existing_seed

    def setup_wrapper(self, *a, **k):
        calls["count"] += 1
        return original_setup(self, *a, **k)

    monkeypatch.setattr(
        manager_module.PasswordManager, "setup_existing_seed", setup_wrapper
    )
    monkeypatch.setattr(manager_module, "prompt_seed_words", lambda *a, **k: TEST_SEED)
    monkeypatch.setattr(
        manager_module.PasswordManager,
        "_finalize_existing_seed",
        lambda self, seed, password=None: "fp",
    )
    monkeypatch.setattr(builtins, "input", lambda *_a, **_k: "2")

    result = pm.add_new_fingerprint()

    assert result == "fp"
    assert calls["count"] == 1
    assert pm.fingerprint_manager.current_fingerprint == "fp"
