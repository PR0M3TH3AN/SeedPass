import sys
from types import SimpleNamespace
from pathlib import Path
import pytest
from seedpass.core.stats_manager import StatsManager

sys.path.append(str(Path(__file__).resolve().parents[1]))

import main


def _make_pm():
    return SimpleNamespace(
        display_stats=lambda: print("stats"),
        start_background_sync=lambda: None,
        stats_manager=StatsManager(),
    )


def test_live_stats_shows_message(monkeypatch, capsys):
    pm = _make_pm()
    monkeypatch.setattr(main, "get_notification_text", lambda *_: "")
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
    monkeypatch.setattr(main, "get_notification_text", lambda *_: "note")
    monkeypatch.setattr(
        main,
        "timed_input",
        lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    main._display_live_stats(pm)
    out = capsys.readouterr().out
    assert "note" in out


def test_live_stats_triggers_background_sync(monkeypatch):
    called = {"sync": 0}

    pm = _make_pm()
    pm.start_background_sync = lambda: called.__setitem__("sync", called["sync"] + 1)

    monkeypatch.setattr(main, "get_notification_text", lambda *_: "")
    monkeypatch.setattr(
        main,
        "timed_input",
        lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()),
    )

    main._display_live_stats(pm)

    assert called["sync"] >= 1


def test_stats_display_only_once(monkeypatch, capsys):
    pm = _make_pm()
    monkeypatch.setattr(main, "get_notification_text", lambda *_: "")

    events = [TimeoutError(), KeyboardInterrupt()]

    def fake_input(*_args, **_kwargs):
        raise events.pop(0)

    monkeypatch.setattr(main, "timed_input", fake_input)
    main._display_live_stats(pm, interval=0.01)
    out = capsys.readouterr().out
    assert out.count("stats") == 1


def test_stats_display_resets_after_exit(monkeypatch, capsys):
    pm = _make_pm()
    monkeypatch.setattr(main, "get_notification_text", lambda *_: "")
    monkeypatch.setattr(
        main,
        "timed_input",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    main._display_live_stats(pm)
    main._display_live_stats(pm)
    out = capsys.readouterr().out
    assert out.count("stats") == 2
