import io

import pytest

from utils import input_utils


def test_timed_input_no_timeout_reads_stdin(monkeypatch):
    monkeypatch.setattr(input_utils.sys, "stdin", io.StringIO(" hello \n"))
    assert input_utils.timed_input("Prompt: ", None) == "hello"


def test_timed_input_dispatches_windows(monkeypatch):
    monkeypatch.setattr(input_utils.sys, "platform", "win32")
    monkeypatch.setattr(
        input_utils, "_timed_input_windows", lambda timeout: f"windows:{timeout}"
    )
    assert input_utils.timed_input("Prompt: ", 1.5) == "windows:1.5"


def test_timed_input_dispatches_posix(monkeypatch):
    monkeypatch.setattr(input_utils.sys, "platform", "linux")
    monkeypatch.setattr(
        input_utils, "_timed_input_posix", lambda timeout: f"posix:{timeout}"
    )
    assert input_utils.timed_input("Prompt: ", 2.0) == "posix:2.0"


def test_timed_input_posix_fileno_fallback(monkeypatch):
    monkeypatch.setattr(input_utils.sys, "stdin", io.StringIO(" via-input \n"))
    assert input_utils._timed_input_posix(timeout=5.0) == "via-input"


def test_timed_input_posix_returns_line_when_ready(monkeypatch):
    class DummyStdin:
        def fileno(self):
            return 0

        def readline(self):
            return "value\n"

    dummy_stdin = DummyStdin()
    monkeypatch.setattr(input_utils.sys, "stdin", dummy_stdin)
    monkeypatch.setattr(
        input_utils.select, "select", lambda r, _w, _x, _t: ([dummy_stdin], [], [])
    )
    assert input_utils._timed_input_posix(timeout=0.1) == "value"


def test_timed_input_posix_raises_timeout(monkeypatch):
    class DummyStdin:
        def fileno(self):
            return 0

    dummy_stdin = DummyStdin()
    monkeypatch.setattr(input_utils.sys, "stdin", dummy_stdin)
    monkeypatch.setattr(
        input_utils.select, "select", lambda _r, _w, _x, _t: ([], [], [])
    )
    with pytest.raises(TimeoutError, match="input timed out"):
        input_utils._timed_input_posix(timeout=0.1)


def test_timed_input_windows_fallback_when_msvcrt_missing(monkeypatch):
    monkeypatch.setattr(input_utils, "msvcrt", None)
    monkeypatch.setattr("builtins.input", lambda: "  typed  ")
    assert input_utils._timed_input_windows(timeout=0.5) == "typed"


def test_timed_input_windows_handles_backspace_and_enter(monkeypatch):
    class DummyMSVCRT:
        def __init__(self):
            self._chars = iter(["a", "\b", "b", "\r"])

        def kbhit(self):
            return True

        def getwche(self):
            return next(self._chars)

    monkeypatch.setattr(input_utils, "msvcrt", DummyMSVCRT())
    monkeypatch.setattr(input_utils.time, "sleep", lambda _s: None)
    monkeypatch.setattr(input_utils.time, "time", lambda: 0.0)

    assert input_utils._timed_input_windows(timeout=10.0) == "b"


def test_timed_input_windows_raises_timeout(monkeypatch):
    class DummyMSVCRT:
        def kbhit(self):
            return False

        def getwche(self):
            return ""

    timestamps = iter([0.0, 2.0])
    monkeypatch.setattr(input_utils, "msvcrt", DummyMSVCRT())
    monkeypatch.setattr(input_utils.time, "sleep", lambda _s: None)
    monkeypatch.setattr(input_utils.time, "time", lambda: next(timestamps))

    with pytest.raises(TimeoutError, match="input timed out"):
        input_utils._timed_input_windows(timeout=1.0)
