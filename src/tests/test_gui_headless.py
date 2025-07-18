import os
from types import SimpleNamespace

import toga

from seedpass_gui.app import LockScreenWindow, MainWindow, EntryDialog


class FakeVault:
    def __init__(self):
        self.called = False

    def unlock(self, request):
        self.called = True


class FakeEntries:
    def __init__(self):
        self.added = []
        self.modified = []

    def list_entries(self):
        return []

    def search_entries(self, query, kinds=None):
        return []

    def add_entry(self, label, length, username=None, url=None):
        self.added.append((label, length, username, url))
        return 1

    def modify_entry(self, entry_id, username=None, url=None, label=None):
        self.modified.append((entry_id, username, url, label))


def setup_module(module):
    os.environ["TOGA_BACKEND"] = "toga_dummy"
    import asyncio

    asyncio.set_event_loop(asyncio.new_event_loop())


class FakeNostr:
    def list_relays(self):
        return []

    def add_relay(self, url):
        pass

    def remove_relay(self, idx):
        pass


def test_unlock_creates_main_window():
    app = toga.App("Test", "org.example")
    controller = SimpleNamespace(main_window=None, nostr_service=FakeNostr())
    vault = FakeVault()
    entries = FakeEntries()
    win = LockScreenWindow(controller, vault, entries)
    win.password_input.value = "pw"
    win.handle_unlock(None)

    assert vault.called
    assert isinstance(controller.main_window, MainWindow)
    controller.main_window.cleanup()


def test_entrydialog_add_calls_service():
    toga.App("Test2", "org.example2")
    entries = FakeEntries()
    main = SimpleNamespace(entries=entries, refresh_entries=lambda: None)

    dlg = EntryDialog(main, None)
    dlg.label_input.value = "L"
    dlg.username_input.value = "u"
    dlg.url_input.value = "x"
    dlg.length_input.value = 12
    dlg.save(None)

    assert entries.added == [("L", 12, "u", "x")]
