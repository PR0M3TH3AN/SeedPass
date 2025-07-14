import queue

from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.manager import PasswordManager, Notification
from constants import NOTIFICATION_DURATION


def _make_pm():
    pm = PasswordManager.__new__(PasswordManager)
    pm.notifications = queue.Queue()
    pm._current_notification = None
    pm._notification_expiry = 0.0
    return pm


def test_notify_sets_current(monkeypatch):
    pm = _make_pm()
    current = {"val": 100.0}
    monkeypatch.setattr("password_manager.manager.time.time", lambda: current["val"])
    pm.notify("hello")
    note = pm._current_notification
    assert hasattr(note, "message")
    assert note.message == "hello"
    assert pm._notification_expiry == 100.0 + NOTIFICATION_DURATION
    assert pm.notifications.qsize() == 1


def test_get_current_notification_ttl(monkeypatch):
    pm = _make_pm()
    now = {"val": 0.0}
    monkeypatch.setattr("password_manager.manager.time.time", lambda: now["val"])
    pm.notify("note1")

    assert pm.get_current_notification().message == "note1"
    assert pm.notifications.qsize() == 1

    now["val"] += NOTIFICATION_DURATION - 1
    assert pm.get_current_notification().message == "note1"

    now["val"] += 2
    assert pm.get_current_notification() is None
