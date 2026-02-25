import os
import toga
import types

import pytest

pytestmark = pytest.mark.desktop

from seedpass.core.pubsub import bus
from seedpass_gui.app import MainWindow, RelayManagerDialog
import seedpass_gui.app


class DummyNostr:
    def __init__(self):
        self.relays = ["wss://a"]

    def list_relays(self):
        return list(self.relays)

    def add_relay(self, url):
        self.relays.append(url)

    def remove_relay(self, idx):
        self.relays.pop(idx - 1)


class DummyEntries:
    def __init__(self):
        self.data = [(1, "Example", None, None, False)]
        self.code = "111111"

    def list_entries(self, sort_by="index", filter_kinds=None, include_archived=False):
        if filter_kinds:
            return [(idx, label, None, None, False) for idx, label, *_ in self.data]
        return self.data

    def search_entries(self, q):
        return []

    def retrieve_entry(self, idx):
        return {"period": 30}

    def get_totp_code(self, idx):
        return self.code


class DummyController:
    def __init__(self):
        self.lock_window = types.SimpleNamespace(show=lambda: None)
        self.main_window = None
        self.vault_service = None
        self.entry_service = None
        self.nostr_service = None


@pytest.fixture(autouse=True)
def set_backend():
    os.environ["TOGA_BACKEND"] = "toga_dummy"
    import asyncio

    asyncio.set_event_loop(asyncio.new_event_loop())


def test_relay_manager_add_remove():
    toga.App("T", "o")
    ctrl = DummyController()
    nostr = DummyNostr()
    win = MainWindow(ctrl, None, DummyEntries(), nostr)
    dlg = RelayManagerDialog(win, nostr)
    dlg.new_input.value = "wss://b"
    dlg.add_relay(None)
    assert nostr.relays == ["wss://a", "wss://b"]
    dlg.remove_relay(None, index=1)
    assert nostr.relays == ["wss://b"]


def test_status_bar_updates_and_lock():
    toga.App("T2", "o2")
    ctrl = DummyController()
    nostr = DummyNostr()
    ctrl.lock_window = types.SimpleNamespace(show=lambda: setattr(ctrl, "locked", True))
    win = MainWindow(ctrl, None, DummyEntries(), nostr)
    ctrl.main_window = win
    bus.publish("sync_started")
    assert win.status.text == "Syncing..."
    bus.publish("sync_finished")
    assert "Last sync:" in win.status.text
    bus.publish("vault_locked")
    assert getattr(ctrl, "locked", False)
    assert ctrl.main_window is None


def test_totp_viewer_refresh_on_sync(monkeypatch):
    toga.App("T3", "o3")
    ctrl = DummyController()
    nostr = DummyNostr()
    entries = DummyEntries()
    win = MainWindow(ctrl, None, entries, nostr)
    ctrl.main_window = win
    ctrl.loop = types.SimpleNamespace(create_task=lambda c: None)

    # prevent background loop from running
    monkeypatch.setattr(
        seedpass_gui.app.TotpViewerWindow, "_update_loop", lambda self: None
    )

    viewer = seedpass_gui.app.TotpViewerWindow(ctrl, entries)
    bus.subscribe("sync_finished", viewer.refresh_codes)

    # Table rows are Row objects with attribute access
    assert viewer.table.data[0].code == "111111"
    entries.code = "222222"
    bus.publish("sync_finished")
    assert viewer.table.data[0].code == "222222"
