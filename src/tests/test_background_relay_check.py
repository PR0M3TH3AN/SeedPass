import time
from types import SimpleNamespace
import queue
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from password_manager.manager import PasswordManager
from constants import MIN_HEALTHY_RELAYS


def test_background_relay_check_runs_async(monkeypatch):
    pm = PasswordManager.__new__(PasswordManager)
    called = {"args": None}
    pm.nostr_client = SimpleNamespace(
        check_relay_health=lambda min_relays: called.__setitem__("args", min_relays)
        or min_relays
    )

    pm.start_background_relay_check()
    time.sleep(0.05)

    assert called["args"] == MIN_HEALTHY_RELAYS


def test_background_relay_check_warns_when_unhealthy(monkeypatch):
    pm = PasswordManager.__new__(PasswordManager)
    pm.notifications = queue.Queue()
    pm.nostr_client = SimpleNamespace(check_relay_health=lambda mr: mr - 1)

    pm.start_background_relay_check()
    time.sleep(0.05)

    note = pm.notifications.get_nowait()
    assert note.level == "WARNING"
    assert str(MIN_HEALTHY_RELAYS - 1) in note.message
