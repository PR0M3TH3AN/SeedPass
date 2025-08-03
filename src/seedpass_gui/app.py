from __future__ import annotations

import asyncio
import time

import toga
from toga.style import Pack
from toga.sources import ListSource
from toga.style.pack import COLUMN, ROW

from seedpass.core.entry_types import EntryType
from seedpass.core.manager import PasswordManager
from seedpass.core.totp import TotpManager

from seedpass.core.api import (
    VaultService,
    EntryService,
    NostrService,
    UnlockRequest,
)
from seedpass.core.pubsub import bus


class LockScreenWindow(toga.Window):
    """Window prompting for the master password."""

    def __init__(
        self,
        controller: SeedPassApp,
        vault: VaultService,
        entries: EntryService,
    ) -> None:
        super().__init__("Unlock Vault")
        # Store a reference to the SeedPass application instance separately from
        # the ``toga`` ``Window.app`` attribute to avoid conflicts.
        self.controller = controller
        self.vault = vault
        self.entries = entries

        self.password_input = toga.PasswordInput(style=Pack(flex=1))
        self.message = toga.Label("", style=Pack(color="red"))
        unlock_button = toga.Button(
            "Unlock", on_press=self.handle_unlock, style=Pack(padding_top=10)
        )

        box = toga.Box(style=Pack(direction=COLUMN, padding=20))
        box.add(toga.Label("Master Password:"))
        box.add(self.password_input)
        box.add(unlock_button)
        box.add(self.message)
        self.content = box

    def handle_unlock(self, widget: toga.Widget) -> None:
        password = self.password_input.value or ""
        try:
            self.vault.unlock(UnlockRequest(password=password))
        except Exception as exc:  # pragma: no cover - GUI error handling
            self.message.text = str(exc)
            return
        main = MainWindow(
            self.controller,
            self.vault,
            self.entries,
            self.controller.nostr_service,
        )
        self.controller.main_window = main
        main.show()
        self.close()


class MainWindow(toga.Window):
    """Main application window showing vault entries."""

    def __init__(
        self,
        controller: SeedPassApp,
        vault: VaultService,
        entries: EntryService,
        nostr: NostrService,
    ) -> None:
        super().__init__("SeedPass", on_close=self.cleanup)
        # ``Window.app`` is reserved for the Toga ``App`` instance. Store the
        # SeedPass application reference separately.
        self.controller = controller
        self.vault = vault
        self.entries = entries
        self.nostr = nostr
        bus.subscribe("sync_started", self.sync_started)
        bus.subscribe("sync_finished", self.sync_finished)
        bus.subscribe("vault_locked", self.vault_locked)
        self.last_sync = None

        self.entry_source = ListSource(["id", "label", "kind", "info1", "info2"])
        self.table = toga.Table(
            headings=["ID", "Label", "Kind", "Info 1", "Info 2"],
            data=self.entry_source,
            style=Pack(flex=1),
        )

        add_button = toga.Button("Add", on_press=self.add_entry)
        edit_button = toga.Button("Edit", on_press=self.edit_entry)
        search_button = toga.Button("Search", on_press=self.search_entries)
        relay_button = toga.Button("Relays", on_press=self.manage_relays)
        totp_button = toga.Button("TOTP", on_press=self.show_totp_codes)
        sync_button = toga.Button("Sync", on_press=self.start_vault_sync)

        button_box = toga.Box(style=Pack(direction=ROW, padding_top=5))
        button_box.add(add_button)
        button_box.add(edit_button)
        button_box.add(search_button)
        button_box.add(relay_button)
        button_box.add(totp_button)
        button_box.add(sync_button)

        self.status = toga.Label("Last sync: never", style=Pack(padding_top=5))

        box = toga.Box(style=Pack(direction=COLUMN, padding=10))
        box.add(self.table)
        box.add(button_box)
        box.add(self.status)
        self.content = box

        self.refresh_entries()

    def refresh_entries(self) -> None:
        self.entry_source.clear()
        for idx, label, username, url, _arch in self.entries.list_entries():
            entry = self.entries.retrieve_entry(idx)
            kind = (entry or {}).get("kind", (entry or {}).get("type", ""))
            info1 = ""
            info2 = ""
            if kind == EntryType.PASSWORD.value:
                info1 = username or ""
                info2 = url or ""
            elif kind == EntryType.KEY_VALUE.value:
                info1 = entry.get("value", "") if entry else ""
            else:
                info1 = str(entry.get("index", "")) if entry else ""
            self.entry_source.append(
                {
                    "id": idx,
                    "label": label,
                    "kind": kind,
                    "info1": info1,
                    "info2": info2,
                }
            )

    # --- Button handlers -------------------------------------------------
    def add_entry(self, widget: toga.Widget) -> None:
        dlg = EntryDialog(self, None)
        dlg.show()

    def edit_entry(self, widget: toga.Widget) -> None:
        if self.table.selection is None:
            return
        entry_id = int(self.table.selection[0])
        dlg = EntryDialog(self, entry_id)
        dlg.show()

    def search_entries(self, widget: toga.Widget) -> None:
        dlg = SearchDialog(self)
        dlg.show()

    def manage_relays(self, widget: toga.Widget) -> None:
        dlg = RelayManagerDialog(self, self.nostr)
        dlg.show()

    def show_totp_codes(self, widget: toga.Widget) -> None:
        win = TotpViewerWindow(self.controller, self.entries)
        win.show()

    def start_vault_sync(self, widget: toga.Widget | None = None) -> None:
        """Schedule a background vault synchronization."""

        async def _runner() -> None:
            self.nostr.start_background_vault_sync()

        self.controller.loop.create_task(_runner())

    # --- PubSub callbacks -------------------------------------------------
    def sync_started(self, *args: object, **kwargs: object) -> None:
        self.status.text = "Syncing..."

    def sync_finished(self, *args: object, **kwargs: object) -> None:
        self.last_sync = time.strftime("%H:%M:%S")
        self.status.text = f"Last sync: {self.last_sync}"

    def vault_locked(self, *args: object, **kwargs: object) -> None:
        self.close()
        self.controller.main_window = None
        self.controller.lock_window.show()

    def cleanup(self, *args: object, **kwargs: object) -> None:
        bus.unsubscribe("sync_started", self.sync_started)
        bus.unsubscribe("sync_finished", self.sync_finished)
        bus.unsubscribe("vault_locked", self.vault_locked)
        manager = getattr(self.nostr, "_manager", None)
        if manager is not None:
            manager.cleanup()


class EntryDialog(toga.Window):
    """Dialog for adding or editing an entry."""

    def __init__(self, main: MainWindow, entry_id: int | None) -> None:
        title = "Add Entry" if entry_id is None else "Edit Entry"
        super().__init__(title)
        self.main = main
        self.entry_id = entry_id

        self.label_input = toga.TextInput(style=Pack(flex=1))
        self.kind_input = toga.Selection(
            items=[e.value for e in EntryType],
            style=Pack(flex=1),
        )
        self.kind_input.value = EntryType.PASSWORD.value
        self.username_input = toga.TextInput(style=Pack(flex=1))
        self.url_input = toga.TextInput(style=Pack(flex=1))
        self.length_input = toga.NumberInput(
            min=8, max=128, style=Pack(width=80), value=16
        )
        self.key_input = toga.TextInput(style=Pack(flex=1))
        self.value_input = toga.TextInput(style=Pack(flex=1))

        save_button = toga.Button(
            "Save", on_press=self.save, style=Pack(padding_top=10)
        )

        box = toga.Box(style=Pack(direction=COLUMN, padding=20))
        box.add(toga.Label("Label"))
        box.add(self.label_input)
        box.add(toga.Label("Kind"))
        box.add(self.kind_input)
        box.add(toga.Label("Username"))
        box.add(self.username_input)
        box.add(toga.Label("URL"))
        box.add(self.url_input)
        box.add(toga.Label("Length"))
        box.add(self.length_input)
        box.add(toga.Label("Key"))
        box.add(self.key_input)
        box.add(toga.Label("Value"))
        box.add(self.value_input)
        box.add(save_button)
        self.content = box

        if entry_id is not None:
            entry = self.main.entries.retrieve_entry(entry_id)
            if entry:
                self.label_input.value = entry.get("label", "")
                kind = entry.get("kind", entry.get("type", EntryType.PASSWORD.value))
                self.kind_input.value = kind
                self.kind_input.enabled = False
                self.username_input.value = entry.get("username", "") or ""
                self.url_input.value = entry.get("url", "") or ""
                self.length_input.value = entry.get("length", 16)
                self.key_input.value = entry.get("key", "")
                self.value_input.value = entry.get("value", "")

    def save(self, widget: toga.Widget) -> None:
        label = self.label_input.value or ""
        username = self.username_input.value or None
        url = self.url_input.value or None
        length = int(self.length_input.value or 16)
        kind = self.kind_input.value
        key = self.key_input.value or None
        value = self.value_input.value or None

        if self.entry_id is None:
            if kind == EntryType.PASSWORD.value:
                entry_id = self.main.entries.add_entry(
                    label, length, username=username, url=url
                )
            elif kind == EntryType.TOTP.value:
                entry_id = self.main.entries.add_totp(label)
            elif kind == EntryType.SSH.value:
                entry_id = self.main.entries.add_ssh_key(label)
            elif kind == EntryType.SEED.value:
                entry_id = self.main.entries.add_seed(label)
            elif kind == EntryType.PGP.value:
                entry_id = self.main.entries.add_pgp_key(label)
            elif kind == EntryType.NOSTR.value:
                entry_id = self.main.entries.add_nostr_key(label)
            elif kind == EntryType.KEY_VALUE.value:
                entry_id = self.main.entries.add_key_value(
                    label, key or "", value or ""
                )
            elif kind == EntryType.MANAGED_ACCOUNT.value:
                entry_id = self.main.entries.add_managed_account(label)
        else:
            entry_id = self.entry_id
            kwargs = {"label": label}
            if kind == EntryType.PASSWORD.value:
                kwargs.update({"username": username, "url": url})
            elif kind == EntryType.KEY_VALUE.value:
                kwargs.update({"key": key, "value": value})
            self.main.entries.modify_entry(entry_id, **kwargs)

        entry = self.main.entries.retrieve_entry(entry_id) or {}
        kind = entry.get("kind", entry.get("type", kind))
        info1 = ""
        info2 = ""
        if kind == EntryType.PASSWORD.value:
            info1 = username or ""
            info2 = url or ""
        elif kind == EntryType.KEY_VALUE.value:
            info1 = entry.get("value", value or "")
        else:
            info1 = str(entry.get("index", ""))

        row = {
            "id": entry_id,
            "label": label,
            "kind": kind,
            "info1": info1,
            "info2": info2,
        }

        if self.entry_id is None:
            self.main.entry_source.append(row)
        else:
            for existing in self.main.entry_source:
                if getattr(existing, "id", None) == entry_id:
                    for key, value in row.items():
                        setattr(existing, key, value)
                    break

        self.close()
        # schedule vault sync after saving
        getattr(self.main, "start_vault_sync", lambda *_: None)()


class SearchDialog(toga.Window):
    """Dialog for searching entries."""

    def __init__(self, main: MainWindow) -> None:
        super().__init__("Search Entries")
        self.main = main
        self.query_input = toga.TextInput(style=Pack(flex=1))
        search_button = toga.Button(
            "Search", on_press=self.do_search, style=Pack(padding_top=10)
        )
        box = toga.Box(style=Pack(direction=COLUMN, padding=20))
        box.add(toga.Label("Query"))
        box.add(self.query_input)
        box.add(search_button)
        self.content = box

    def do_search(self, widget: toga.Widget) -> None:
        query = self.query_input.value or ""
        results = self.main.entries.search_entries(query)
        self.main.entry_source.clear()
        for idx, label, username, url, _arch, _etype in results:
            self.main.entry_source.append(
                {
                    "id": idx,
                    "label": label,
                    "kind": "",
                    "info1": username or "",
                    "info2": url or "",
                }
            )
        self.close()


class TotpViewerWindow(toga.Window):
    """Window displaying active TOTP codes."""

    def __init__(self, controller: SeedPassApp, entries: EntryService) -> None:
        super().__init__("TOTP Codes", on_close=self.cleanup)
        self.controller = controller
        self.entries = entries

        self.table = toga.Table(
            headings=["Label", "Code", "Seconds"],
            style=Pack(flex=1),
        )

        box = toga.Box(style=Pack(direction=COLUMN, padding=20))
        box.add(self.table)
        self.content = box

        self._running = True
        self.controller.loop.create_task(self._update_loop())
        self.refresh_codes()

    async def _update_loop(self) -> None:
        while self._running:
            self.refresh_codes()
            await asyncio.sleep(1)

    def refresh_codes(self) -> None:
        self.table.data = []
        for idx, label, *_rest in self.entries.list_entries(
            filter_kind=EntryType.TOTP.value
        ):
            entry = self.entries.retrieve_entry(idx)
            code = self.entries.get_totp_code(idx)
            period = int(entry.get("period", 30)) if entry else 30
            remaining = TotpManager.time_remaining(period)
            self.table.data.append((label, code, remaining))

    def cleanup(self, *args: object, **kwargs: object) -> None:
        self._running = False


class RelayManagerDialog(toga.Window):
    """Dialog for managing relay URLs."""

    def __init__(self, main: MainWindow, nostr: NostrService) -> None:
        super().__init__("Relays")
        self.main = main
        self.nostr = nostr

        self.table = toga.Table(headings=["Index", "URL"], style=Pack(flex=1))
        self.new_input = toga.TextInput(style=Pack(flex=1))
        add_btn = toga.Button("Add", on_press=self.add_relay)
        remove_btn = toga.Button("Remove", on_press=self.remove_relay)
        self.message = toga.Label("", style=Pack(color="red"))

        box = toga.Box(style=Pack(direction=COLUMN, padding=20))
        box.add(self.table)
        form = toga.Box(style=Pack(direction=ROW, padding_top=5))
        form.add(self.new_input)
        form.add(add_btn)
        form.add(remove_btn)
        box.add(form)
        box.add(self.message)
        self.content = box

        self.refresh()

    def refresh(self) -> None:
        self.table.data = []
        for i, url in enumerate(self.nostr.list_relays(), start=1):
            self.table.data.append((i, url))

    def add_relay(self, widget: toga.Widget) -> None:
        url = self.new_input.value or ""
        if not url:
            return
        try:
            self.nostr.add_relay(url)
        except Exception as exc:  # pragma: no cover - pass errors
            self.message.text = str(exc)
            return
        self.new_input.value = ""
        self.refresh()

    def remove_relay(self, widget: toga.Widget, *, index: int | None = None) -> None:
        if index is None:
            if self.table.selection is None:
                return
            index = int(self.table.selection[0])
        try:
            self.nostr.remove_relay(index)
        except Exception as exc:  # pragma: no cover - pass errors
            self.message.text = str(exc)
            return
        self.refresh()


def build() -> SeedPassApp:
    """Return a configured :class:`SeedPassApp` instance."""
    return SeedPassApp(formal_name="SeedPass", app_id="org.seedpass.gui")


class SeedPassApp(toga.App):
    def startup(self) -> None:  # pragma: no cover - GUI bootstrap
        pm = PasswordManager()
        self.vault_service = VaultService(pm)
        self.entry_service = EntryService(pm)
        self.nostr_service = NostrService(pm)
        self.lock_window = LockScreenWindow(
            self,
            self.vault_service,
            self.entry_service,
        )
        self.main_window = None
        self.lock_window.show()


def main() -> None:  # pragma: no cover - GUI bootstrap
    """Run the BeeWare application."""
    build().main_loop()
