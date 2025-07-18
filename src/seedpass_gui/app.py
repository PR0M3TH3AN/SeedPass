from __future__ import annotations

import toga
from toga.style import Pack
from toga.style.pack import COLUMN, ROW

from seedpass.core.manager import PasswordManager
from seedpass.core.api import (
    VaultService,
    EntryService,
    UnlockRequest,
)


class LockScreenWindow(toga.Window):
    """Window prompting for the master password."""

    def __init__(
        self, controller: SeedPassApp, vault: VaultService, entries: EntryService
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
        main = MainWindow(self.controller, self.vault, self.entries)
        self.controller.main_window = main
        main.show()
        self.close()


class MainWindow(toga.Window):
    """Main application window showing vault entries."""

    def __init__(
        self, controller: SeedPassApp, vault: VaultService, entries: EntryService
    ) -> None:
        super().__init__("SeedPass")
        # ``Window.app`` is reserved for the Toga ``App`` instance. Store the
        # SeedPass application reference separately.
        self.controller = controller
        self.vault = vault
        self.entries = entries

        self.table = toga.Table(
            headings=["ID", "Label", "Username", "URL"], style=Pack(flex=1)
        )

        add_button = toga.Button("Add", on_press=self.add_entry)
        edit_button = toga.Button("Edit", on_press=self.edit_entry)
        search_button = toga.Button("Search", on_press=self.search_entries)

        button_box = toga.Box(style=Pack(direction=ROW, padding_top=5))
        button_box.add(add_button)
        button_box.add(edit_button)
        button_box.add(search_button)

        box = toga.Box(style=Pack(direction=COLUMN, padding=10))
        box.add(self.table)
        box.add(button_box)
        self.content = box

        self.refresh_entries()

    def refresh_entries(self) -> None:
        self.table.data = []
        for idx, label, username, url, _arch in self.entries.list_entries():
            self.table.data.append((idx, label, username or "", url or ""))

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


class EntryDialog(toga.Window):
    """Dialog for adding or editing an entry."""

    def __init__(self, main: MainWindow, entry_id: int | None) -> None:
        title = "Add Entry" if entry_id is None else "Edit Entry"
        super().__init__(title)
        self.main = main
        self.entry_id = entry_id

        self.label_input = toga.TextInput(style=Pack(flex=1))
        self.username_input = toga.TextInput(style=Pack(flex=1))
        self.url_input = toga.TextInput(style=Pack(flex=1))
        self.length_input = toga.NumberInput(
            min=8, max=128, style=Pack(width=80), value=16
        )

        save_button = toga.Button(
            "Save", on_press=self.save, style=Pack(padding_top=10)
        )

        box = toga.Box(style=Pack(direction=COLUMN, padding=20))
        box.add(toga.Label("Label"))
        box.add(self.label_input)
        box.add(toga.Label("Username"))
        box.add(self.username_input)
        box.add(toga.Label("URL"))
        box.add(self.url_input)
        box.add(toga.Label("Length"))
        box.add(self.length_input)
        box.add(save_button)
        self.content = box

        if entry_id is not None:
            entry = self.main.entries.retrieve_entry(entry_id)
            if entry:
                self.label_input.value = entry.get("label", "")
                self.username_input.value = entry.get("username", "") or ""
                self.url_input.value = entry.get("url", "") or ""
                self.length_input.value = entry.get("length", 16)

    def save(self, widget: toga.Widget) -> None:
        label = self.label_input.value or ""
        username = self.username_input.value or None
        url = self.url_input.value or None
        length = int(self.length_input.value or 16)

        if self.entry_id is None:
            self.main.entries.add_entry(label, length, username=username, url=url)
        else:
            self.main.entries.modify_entry(
                self.entry_id, username=username, url=url, label=label
            )
        self.main.refresh_entries()
        self.close()


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
        self.main.table.data = []
        for idx, label, username, url, _arch in results:
            self.main.table.data.append((idx, label, username or "", url or ""))
        self.close()


def build() -> SeedPassApp:
    """Return a configured :class:`SeedPassApp` instance."""
    return SeedPassApp(formal_name="SeedPass", app_id="org.seedpass.gui")


class SeedPassApp(toga.App):
    def startup(self) -> None:  # pragma: no cover - GUI bootstrap
        pm = PasswordManager()
        self.vault_service = VaultService(pm)
        self.entry_service = EntryService(pm)
        self.lock_window = LockScreenWindow(
            self, self.vault_service, self.entry_service
        )
        self.main_window = None
        self.lock_window.show()


def main() -> None:  # pragma: no cover - GUI bootstrap
    """Run the BeeWare application."""
    build().main_loop()
