import builtins
from types import SimpleNamespace

import pytest

import seedpass.core.manager as manager_module
from helpers import TEST_SEED
from utils import seed_prompt


def test_prompt_seed_words_confirmation_loop(monkeypatch):
    phrase = TEST_SEED
    words = phrase.split()
    inputs = iter(words + [words[2]])
    confirmations = iter(["y", "y", "n", "y"] + ["y"] * (len(words) - 3))

    monkeypatch.setattr(seed_prompt, "masked_input", lambda *_: next(inputs))
    monkeypatch.setattr(seed_prompt, "_apply_backoff", lambda *_a, **_k: None)
    monkeypatch.setattr(seed_prompt, "clear_screen", lambda *_a, **_k: None)
    monkeypatch.setattr(builtins, "input", lambda *_: next(confirmations))

    result = seed_prompt.prompt_seed_words(len(words))
    assert result == phrase


def test_prompt_seed_words_invalid_word(monkeypatch):
    phrase = TEST_SEED
    words = phrase.split()
    inputs = iter(["invalid"] + words)
    confirmations = iter(["y"] * len(words))

    monkeypatch.setattr(seed_prompt, "masked_input", lambda *_: next(inputs))
    monkeypatch.setattr(seed_prompt, "_apply_backoff", lambda *_a, **_k: None)
    monkeypatch.setattr(seed_prompt, "clear_screen", lambda *_a, **_k: None)
    monkeypatch.setattr(builtins, "input", lambda *_: next(confirmations))

    result = seed_prompt.prompt_seed_words(len(words))
    assert result == phrase


def test_add_new_fingerprint_words_flow_success(monkeypatch):
    pm = manager_module.PasswordManager.__new__(manager_module.PasswordManager)
    pm.fingerprint_manager = SimpleNamespace(current_fingerprint=None)
    pm.initialize_managers = lambda: None

    phrase = TEST_SEED
    words = phrase.split()
    word_iter = iter(words)
    inputs = iter(["2"] + ["y"] * len(words))

    monkeypatch.setattr(seed_prompt, "masked_input", lambda *_: next(word_iter))
    monkeypatch.setattr(seed_prompt, "_apply_backoff", lambda *_a, **_k: None)
    monkeypatch.setattr(seed_prompt, "clear_screen", lambda *_a, **_k: None)
    monkeypatch.setattr(builtins, "input", lambda *_: next(inputs))

    captured = {}

    def finalize(self, seed, password=None):
        captured["seed"] = seed
        self.parent_seed = seed
        return "fp"

    monkeypatch.setattr(
        manager_module.PasswordManager, "_finalize_existing_seed", finalize
    )

    result = pm.add_new_fingerprint()

    assert result == "fp"
    assert pm.fingerprint_manager.current_fingerprint == "fp"
    assert captured["seed"] == phrase
    assert pm.parent_seed == phrase


def test_add_new_fingerprint_words_flow_invalid_phrase(monkeypatch):
    pm = manager_module.PasswordManager.__new__(manager_module.PasswordManager)
    pm.fingerprint_manager = SimpleNamespace(current_fingerprint=None)
    pm.initialize_managers = lambda: None

    words = ["abandon"] * 12
    word_iter = iter(words)
    inputs = iter(["2"] + ["y"] * len(words))

    monkeypatch.setattr(seed_prompt, "masked_input", lambda *_: next(word_iter))
    monkeypatch.setattr(seed_prompt, "_apply_backoff", lambda *_a, **_k: None)
    monkeypatch.setattr(seed_prompt, "clear_screen", lambda *_a, **_k: None)
    monkeypatch.setattr(builtins, "input", lambda *_: next(inputs))

    with pytest.raises(SystemExit):
        pm.add_new_fingerprint()

    assert pm.fingerprint_manager.current_fingerprint is None
    assert not hasattr(pm, "parent_seed")
