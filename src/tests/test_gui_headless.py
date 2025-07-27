import os
from types import SimpleNamespace
from toga.sources import ListSource

import toga
import pytest

from seedpass.core.entry_types import EntryType

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
        self.added.append(("password", label, length, username, url))
        return 1

    def add_totp(self, label):
        self.added.append(("totp", label))
        return 1

    def add_ssh_key(self, label):
        self.added.append(("ssh", label))
        return 1

    def add_seed(self, label):
        self.added.append(("seed", label))
        return 1

    def add_pgp_key(self, label):
        self.added.append(("pgp", label))
        return 1

    def add_nostr_key(self, label):
        self.added.append(("nostr", label))
        return 1

    def add_key_value(self, label, value):
        self.added.append(("key_value", label, value))
        return 1

    def add_managed_account(self, label):
        self.added.append(("managed_account", label))
        return 1

    def modify_entry(self, entry_id, username=None, url=None, label=None, value=None):
        self.modified.append((entry_id, username, url, label, value))


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


@pytest.mark.parametrize(
    "kind,expect",
    [
        (EntryType.PASSWORD.value, ("password", "L", 12, "u", "x")),
        (EntryType.TOTP.value, ("totp", "L")),
        (EntryType.SSH.value, ("ssh", "L")),
        (EntryType.SEED.value, ("seed", "L")),
        (EntryType.PGP.value, ("pgp", "L")),
        (EntryType.NOSTR.value, ("nostr", "L")),
        (EntryType.KEY_VALUE.value, ("key_value", "L", "val")),
        (EntryType.MANAGED_ACCOUNT.value, ("managed_account", "L")),
    ],
)
def test_entrydialog_add_calls_service(kind, expect):
    toga.App("Test2", "org.example2")
    entries = FakeEntries()
    entries.retrieve_entry = lambda _id: {"kind": kind}
    source = ListSource(["id", "label", "kind", "info1", "info2"])
    main = SimpleNamespace(entries=entries, entry_source=source)

    dlg = EntryDialog(main, None)
    dlg.label_input.value = "L"
    dlg.kind_input.value = kind
    dlg.username_input.value = "u"
    dlg.url_input.value = "x"
    dlg.length_input.value = 12
    dlg.value_input.value = "val"
    dlg.save(None)

    assert entries.added[-1] == expect
    assert len(main.entry_source) == 1
    row = main.entry_source[0]
    assert row.label == "L"
    assert row.kind == kind


@pytest.mark.parametrize(
    "kind,expected",
    [
        (EntryType.PASSWORD.value, (1, "newu", "newx", "New", None)),
        (EntryType.KEY_VALUE.value, (1, None, None, "New", "val2")),
        (EntryType.TOTP.value, (1, None, None, "New", None)),
    ],
)
def test_entrydialog_edit_calls_service(kind, expected):
    toga.App("Edit", "org.edit")
    entries = FakeEntries()

    def retrieve(_id):
        return {"kind": kind}

    entries.retrieve_entry = retrieve
    source = ListSource(["id", "label", "kind", "info1", "info2"])
    source.append({"id": 1, "label": "Old", "kind": kind, "info1": "", "info2": ""})
    main = SimpleNamespace(entries=entries, entry_source=source)
    dlg = EntryDialog(main, 1)
    dlg.label_input.value = "New"
    dlg.kind_input.value = kind
    dlg.username_input.value = "newu"
    dlg.url_input.value = "newx"
    dlg.value_input.value = "val2"
    dlg.save(None)

    assert entries.modified[-1] == expected
    assert source[0].label == "New"
