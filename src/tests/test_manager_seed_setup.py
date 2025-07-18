import builtins
from mnemonic import Mnemonic
from password_manager.manager import PasswordManager
from utils import seed_prompt


def test_validate_bip85_seed_invalid_word():
    pm = PasswordManager.__new__(PasswordManager)
    bad_phrase = "abandon " * 11 + "zzzz"
    assert not pm.validate_bip85_seed(bad_phrase)


def test_validate_bip85_seed_checksum_failure():
    pm = PasswordManager.__new__(PasswordManager)
    # Use a known valid phrase to avoid randomness causing a valid checksum
    phrase = (
        "legal winner thank year wave sausage worth useful legal winner thank yellow"
    )
    words = phrase.split()
    words[-1] = "abandon"
    bad_phrase = " ".join(words)
    assert not pm.validate_bip85_seed(bad_phrase)


def test_setup_existing_seed_words(monkeypatch):
    m = Mnemonic("english")
    phrase = m.generate(strength=128)
    words = phrase.split()
    word_iter = iter(words)
    monkeypatch.setattr(
        "password_manager.manager.masked_input",
        lambda *_: next(word_iter),
    )
    # Ensure prompt_seed_words uses the patched function
    monkeypatch.setattr(seed_prompt, "masked_input", lambda *_: next(word_iter))
    monkeypatch.setattr(builtins, "input", lambda *_: "y")

    pm = PasswordManager.__new__(PasswordManager)
    monkeypatch.setattr(pm, "_finalize_existing_seed", lambda seed: seed)

    result = pm.setup_existing_seed(method="words")
    assert result == phrase


def test_setup_existing_seed_paste(monkeypatch):
    m = Mnemonic("english")
    phrase = m.generate(strength=128)

    called = {}

    def fake_masked_input(prompt: str) -> str:
        called["prompt"] = prompt
        return phrase

    monkeypatch.setattr("password_manager.manager.masked_input", fake_masked_input)
    monkeypatch.setattr(
        builtins,
        "input",
        lambda *_: (_ for _ in ()).throw(RuntimeError("input called")),
    )

    pm = PasswordManager.__new__(PasswordManager)
    monkeypatch.setattr(pm, "_finalize_existing_seed", lambda seed: seed)

    result = pm.setup_existing_seed(method="paste")
    assert result == phrase
    assert called["prompt"].startswith("Enter your 12-word BIP-85 seed")
