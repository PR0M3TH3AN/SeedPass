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
