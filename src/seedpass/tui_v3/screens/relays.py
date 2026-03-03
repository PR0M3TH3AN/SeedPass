from __future__ import annotations
from typing import Any
from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Static, Footer, DataTable, Input, Button
from textual.containers import Vertical, Horizontal

class RelaysScreen(Screen):
    """
    A dedicated screen for managing Nostr relays and triggering synchronization.
    """
    
    BINDINGS = [
        ("escape", "app.pop_screen", "Back to Vault"),
        ("r", "refresh_relays", "Refresh"),
        ("d", "delete_relay", "Delete Relay"),
        ("s", "sync_now", "Sync Now"),
    ]

    DEFAULT_CSS = """
    RelaysScreen {
        background: #999999;
    }
    #relays-title {
        background: #000000;
        color: #ffffff;
        text-style: bold;
        text-align: center;
        height: 3;
        border: solid #000000;
        padding: 0 1;
        margin: 1 2;
    }
    #relays-container {
        height: 1fr;
        margin: 0 2;
        border: solid #000000;
        padding: 1;
        background: #999999;
    }
    #relays-table {
        height: 1fr;
        border: solid #000000;
        background: #ffffff;
        color: #000000;
    }
    #relays-controls {
        height: 3;
        margin-top: 1;
        align: left middle;
    }
    #relay-input {
        width: 1fr;
        border: solid black;
        background: #ffffff;
        color: #000000;
    }
    #add-button {
        background: #000000;
        color: #ffffff;
        border: solid black;
        margin-left: 1;
    }
    #add-button:hover {
        background: #ffffff;
        color: #000000;
    }
    #relays-footer {
        height: 3;
        background: #000000;
        color: #ffffff;
        text-align: center;
        border: solid #000000;
        padding: 0 1;
        margin: 1 2;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static("SeedPass ◈ Nostr Relay Management", id="relays-title")
        with Vertical(id="relays-container"):
            yield DataTable(id="relays-table")
            with Horizontal(id="relays-controls"):
                yield Input(placeholder="wss://relay.example.com", id="relay-input")
                yield Button("Add Relay", id="add-button")
        yield Static("ESC: Exit | R: Refresh | D: Delete Selected | S: Sync Now", id="relays-footer")

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.cursor_type = "row"
        table.add_columns("Status", "URL")
        self.action_refresh_relays()

    def action_refresh_relays(self) -> None:
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
            self.app.notify("Relay URL must start with ws:// or wss://", severity="error")
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
        except Exception as e:
            self.app.notify(f"Failed to add relay: {e}", severity="error")

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

        service = self.app.services.get("nostr")
        if not service:
            return
            
        try:
            service.remove_relay(idx)
            self.action_refresh_relays()
            self.app.notify(f"Removed relay: {url}")
        except Exception as e:
            self.app.notify(f"Failed to remove relay: {e}", severity="error")

    def action_sync_now(self) -> None:
        sync_service = self.app.services.get("sync")
        if not sync_service:
            self.app.notify("Sync service offline", severity="error")
            return

        self.app.notify("Starting Nostr synchronization...", severity="information")
        self.run_worker(self._perform_sync, exclusive=True)

    async def _perform_sync(self) -> None:
        sync_service = self.app.services.get("sync")
        try:
            import traceback
            sync_service.sync()
            self.app.call_from_thread(self.app.notify, "Synchronization complete", severity="information")
            self.app.call_from_thread(self.app.action_refresh)
        except Exception as e:
            self.app.call_from_thread(self.app.notify, f"Sync failed: {e}", severity="error")
