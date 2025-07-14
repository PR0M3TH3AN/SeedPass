import sys
from types import SimpleNamespace
from pathlib import Path
import pytest

sys.path.append(str(Path(__file__).resolve().parents[1]))

import main


def _make_pm():
    return SimpleNamespace(display_stats=lambda: print("stats"))


def test_live_stats_shows_message(monkeypatch, capsys):
    pm = _make_pm()
    monkeypatch.setattr(main, "drain_notifications", lambda *_: None)
    monkeypatch.setattr(
        main,
        "timed_input",
        lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    main._display_live_stats(pm)
    out = capsys.readouterr().out
    assert "Press Enter to continue." in out


def test_live_stats_shows_notification(monkeypatch, capsys):
    pm = _make_pm()
    monkeypatch.setattr(main, "drain_notifications", lambda *_: "note")
    monkeypatch.setattr(
        main,
        "timed_input",
        lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    main._display_live_stats(pm)
    out = capsys.readouterr().out
    assert "note" in out
