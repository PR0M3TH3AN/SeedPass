import os
import types
import asyncio
import toga
import pytest

from seedpass.core.pubsub import bus
from seedpass_gui.app import MainWindow


class DummyEntries:
    def list_entries(self, sort_by="index", filter_kind=None, include_archived=False):
        return []

    def search_entries(self, q):
        return []


class DummyNostr:
    def __init__(self):
        self.called = False

    def start_background_vault_sync(self):
        self.called = True

    def list_relays(self):
        return []


class DummyController:
    def __init__(self, loop):
        self.loop = loop
        self.lock_window = types.SimpleNamespace(show=lambda: None)
        self.main_window = None
        self.vault_service = None
        self.entry_service = None
        self.nostr_service = None


@pytest.fixture(autouse=True)
def set_backend():
    os.environ["TOGA_BACKEND"] = "toga_dummy"
    asyncio.set_event_loop(asyncio.new_event_loop())


def test_start_vault_sync_schedules_task():
    toga.App("T", "o")

    tasks = []

    def create_task(coro):
        tasks.append(coro)

    loop = types.SimpleNamespace(create_task=create_task)
    ctrl = DummyController(loop)
    nostr = DummyNostr()
    win = MainWindow(ctrl, None, DummyEntries(), nostr)

    win.start_vault_sync()
    assert tasks
    asyncio.get_event_loop().run_until_complete(tasks[0])
    assert nostr.called


def test_status_updates_on_bus_events():
    toga.App("T2", "o2")
    loop = types.SimpleNamespace(create_task=lambda c: None)
    ctrl = DummyController(loop)
    nostr = DummyNostr()
    win = MainWindow(ctrl, None, DummyEntries(), nostr)

    bus.publish("sync_started")
    assert win.status.text == "Syncing..."
    bus.publish("sync_finished")
    assert "Last sync:" in win.status.text
