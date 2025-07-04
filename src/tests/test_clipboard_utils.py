from pathlib import Path
import pyperclip
import threading

import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from utils.clipboard import copy_to_clipboard


def test_copy_to_clipboard_clears(monkeypatch):
    clipboard = {"text": ""}

    def fake_copy(val):
        clipboard["text"] = val

    def fake_paste():
        return clipboard["text"]

    callbacks = {}

    class DummyTimer:
        def __init__(self, delay, func):
            callbacks["delay"] = delay
            callbacks["func"] = func

        def start(self):
            callbacks["started"] = True

    monkeypatch.setattr(pyperclip, "copy", fake_copy)
    monkeypatch.setattr(pyperclip, "paste", fake_paste)
    monkeypatch.setattr(threading, "Timer", DummyTimer)

    copy_to_clipboard("secret", 2)
    assert clipboard["text"] == "secret"
    assert callbacks["delay"] == 2
    assert callbacks["started"]
    callbacks["func"]()
    assert clipboard["text"] == ""


def test_copy_to_clipboard_does_not_clear_if_changed(monkeypatch):
    clipboard = {"text": ""}

    def fake_copy(val):
        clipboard["text"] = val

    def fake_paste():
        return clipboard["text"]

    callbacks = {}

    class DummyTimer:
        def __init__(self, delay, func):
            callbacks["func"] = func

        def start(self):
            pass

    monkeypatch.setattr(pyperclip, "copy", fake_copy)
    monkeypatch.setattr(pyperclip, "paste", fake_paste)
    monkeypatch.setattr(threading, "Timer", DummyTimer)

    copy_to_clipboard("secret", 1)
    fake_copy("other")
    callbacks["func"]()
    assert clipboard["text"] == "other"
