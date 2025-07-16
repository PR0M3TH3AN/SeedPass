import types
from utils import seed_prompt


def test_masked_input_posix_backspace(monkeypatch, capsys):
    seq = iter(["a", "b", "\x7f", "c", "\n"])
    monkeypatch.setattr(seed_prompt.sys.stdin, "read", lambda n=1: next(seq))
    monkeypatch.setattr(seed_prompt.sys.stdin, "fileno", lambda: 0)
    monkeypatch.setattr(seed_prompt.termios, "tcgetattr", lambda fd: None)
    monkeypatch.setattr(seed_prompt.termios, "tcsetattr", lambda fd, *_: None)
    monkeypatch.setattr(seed_prompt.tty, "setraw", lambda fd: None)

    result = seed_prompt.masked_input("Enter: ")
    assert result == "ac"
    out = capsys.readouterr().out
    assert out.startswith("Enter: ")
    assert out.count("*") == 3


def test_masked_input_windows_space(monkeypatch, capsys):
    seq = iter(["x", "y", " ", "z", "\r"])
    fake_msvcrt = types.SimpleNamespace(getwch=lambda: next(seq))
    monkeypatch.setattr(seed_prompt, "msvcrt", fake_msvcrt)
    monkeypatch.setattr(seed_prompt.sys, "platform", "win32", raising=False)

    result = seed_prompt.masked_input("Password: ")
    assert result == "xy z"
    out = capsys.readouterr().out
    assert out.startswith("Password: ")
    assert out.count("*") == 4


def test_prompt_seed_words_valid(monkeypatch):
    from mnemonic import Mnemonic

    m = Mnemonic("english")
    phrase = m.generate(strength=128)
    words = phrase.split()

    inputs = iter(words + ["y"] * len(words))
    monkeypatch.setattr(seed_prompt, "masked_input", lambda *_: next(inputs))
    monkeypatch.setattr("builtins.input", lambda *_: next(inputs))

    result = seed_prompt.prompt_seed_words(len(words))
    assert result == phrase


def test_prompt_seed_words_invalid_word(monkeypatch):
    from mnemonic import Mnemonic

    m = Mnemonic("english")
    phrase = m.generate(strength=128)
    words = phrase.split()
    # Insert an invalid word for the first entry then the correct one
    inputs = iter(["invalid"] + [words[0]] + words[1:] + ["y"] * len(words))
    monkeypatch.setattr(seed_prompt, "masked_input", lambda *_: next(inputs))
    monkeypatch.setattr("builtins.input", lambda *_: next(inputs))

    result = seed_prompt.prompt_seed_words(len(words))
    assert result == phrase
