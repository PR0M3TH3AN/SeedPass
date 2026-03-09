from __future__ import annotations
from typing import Any
from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Static, Footer, DataTable, Input, Button
from textual.containers import Vertical, Horizontal

from .maintenance import MAINTENANCE_CSS, format_status


class RelaysScreen(Screen):
    """
    A dedicated screen for managing Nostr relays and triggering synchronization.
    """

    def __init__(self) -> None:
        super().__init__()
        self._pending_delete_idx: int | None = None

    BINDINGS = [
        ("escape", "app.pop_screen", "Back to Vault"),
        ("r", "refresh_relays", "Refresh"),
        ("d", "delete_relay", "Delete Relay"),
        ("s", "sync_now", "Sync Now"),
    ]

    CSS = (
        MAINTENANCE_CSS
        + """
    RelaysScreen {
        background: #999999;
    }
    #relays-container {
        height: 1fr;
    }
    #relays-table {
        height: 1fr;
        border: solid #666666;
    }
    #relays-controls {
        height: 3;
        margin-top: 1;
        align: left middle;
    }
    #relays-status {
        min-height: 3;
    }
    #relay-input {
        width: 1fr;
    }
    #add-button {
        margin-left: 1;
        min-width: 16;
    }
    """
    )

    def compose(self) -> ComposeResult:
        yield Static("SeedPass ◈ Nostr Relay Management", classes="maintenance-title")
        with Vertical(id="relays-container", classes="maintenance-panel-light"):
            yield Static(
                "Manage Nostr relay endpoints for this profile. Add new relays or remove existing ones. Deletions require a second confirmation press.",
                id="relays-intro",
                classes="maintenance-intro-light",
            )
            yield DataTable(id="relays-table")
            with Horizontal(id="relays-controls"):
                yield Input(
                    placeholder="wss://relay.example.com",
                    id="relay-input",
                    classes="maintenance-input",
                )
                yield Button("Add Relay", id="add-button", classes="maintenance-primary")
            yield Static(
                format_status("ready", "Select a relay or add a new endpoint."),
                id="relays-status",
                classes="maintenance-status-light",
            )
        yield Static(
            "ESC: Back | R: Refresh | D: Delete selected | S: Sync now",
            classes="maintenance-footer",
        )

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.cursor_type = "row"
        table.add_columns("Status", "URL")
        self.action_refresh_relays()

    def action_refresh_relays(self) -> None:
        self._pending_delete_idx = None
        app = self.app
        if "nostr" not in app.services:
            self.app.notify("Nostr Service Offline", severity="error")
            return

        service = app.services["nostr"]
        try:
            relays = service.list_relays()
        except Exception:
            relays = []

        table = self.query_one(DataTable)
        table.clear()
        for idx, url in enumerate(relays):
            table.add_row("🟢 Active", url, key=str(idx))
        self._set_status(format_status("ready", f"{len(relays)} relay(s) loaded."))

    def _set_status(self, message: str) -> None:
        self.query_one("#relays-status", Static).update(message)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "add-button":
            self._add_relay()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "relay-input":
            self._add_relay()

    def _add_relay(self) -> None:
        inp = self.query_one(Input)
        url = inp.value.strip()
        if not url:
            return

        if not url.startswith("ws://") and not url.startswith("wss://"):
            self.app.notify(
                "Relay URL must start with ws:// or wss://", severity="error"
            )
            return

        service = self.app.services.get("nostr")
        if not service:
            return

        try:
            relays = service.list_relays()
            if url in relays:
                self.app.notify("Relay already exists", severity="warning")
                return

            service.add_relay(url)
            inp.value = ""
            self.action_refresh_relays()
            self.app.notify(f"Added relay: {url}")
            self._set_status(format_status("success", f"Added relay {url}"))
        except Exception as e:
            self.app.notify(f"Failed to add relay: {e}", severity="error")
            self._set_status(format_status("error", f"Add relay failed: {e}"))

    def action_delete_relay(self) -> None:
        table = self.query_one(DataTable)
        try:
            curr_coord = table.cursor_coordinate
            if curr_coord.row < 0:
                self.app.notify("No relay selected", severity="warning")
                return
            row_key = table.coordinate_to_cell_key(curr_coord).row_key
            idx = int(row_key.value)
            url = table.get_row(row_key)[1]
        except Exception:
            self.app.notify("No relay selected", severity="warning")
            return

        if self._pending_delete_idx != idx:
            self._pending_delete_idx = idx
            self._set_status(
                format_status("warning", f"Press Delete again to remove relay {url}")
            )
            return

        service = self.app.services.get("nostr")
        if not service:
            return

        try:
            self._pending_delete_idx = None
            service.remove_relay(idx)
            self.action_refresh_relays()
            self.app.notify(f"Removed relay: {url}")
            self._set_status(format_status("success", f"Removed relay {url}"))
        except Exception as e:
            self.app.notify(f"Failed to remove relay: {e}", severity="error")
            self._set_status(format_status("error", f"Delete relay failed: {e}"))

    def action_sync_now(self) -> None:
        sync_service = self.app.services.get("sync")
        if not sync_service:
            self.app.notify("Sync service offline", severity="error")
            return

        self.app.notify("Starting Nostr synchronization...", severity="information")
        self._set_status(format_status("working", "Starting Nostr synchronization..."))
        self.run_worker(self._perform_sync, exclusive=True)

    async def _perform_sync(self) -> None:
        sync_service = self.app.services.get("sync")
        try:
            sync_service.sync()
            self.app.call_from_thread(
                self.app.notify, "Synchronization complete", severity="information"
            )
            self.app.call_from_thread(
                self._set_status, format_status("success", "Synchronization complete.")
            )
            self.app.call_from_thread(self.app.action_refresh)
        except Exception as e:
            self.app.call_from_thread(
                self.app.notify, f"Sync failed: {e}", severity="error"
            )
            self.app.call_from_thread(
                self._set_status, format_status("error", f"Sync failed: {e}")
            )
