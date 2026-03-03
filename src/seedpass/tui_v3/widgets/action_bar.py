from __future__ import annotations
from typing import Any
from textual.app import ComposeResult
from textual.widgets import Static
from textual.reactive import reactive

class ActionBar(Static):
    """
    Bottom action bar showing global shortcuts and context actions.
    Matches the 'Settings (S)  Add (A) ...' layout.
    """
    
    DEFAULT_CSS = """
    ActionBar {
        height: 3;
        background: #11191f;
        color: #daf2e5;
        border: heavy #2abf75;
        padding: 0 1;
        margin: 0 1;
    }
    """

    def render(self) -> str:
        app = self.app
        selected_id = app.selected_entry_id
        
        # Global Row
        global_row = (
            "Settings (Shift+S)  Add (Shift+A)  Seed+ (Shift+C)  "
            "Reveal (Shift+H)  Backup (B)  Cmd (Ctrl+P)"
        )
        
        # Context Row
        if selected_id is None:
            context = "Select an entry to view actions."
        else:
            # We would normally determine kind here
            context = f"Entry #{selected_id} ▣ Reveal (v) ▣ QR (g) ▣ Edit (e) ▣ Archive (a) ▣ Max (z)"
            
        return f"{global_row}
{context}"

    def on_mount(self) -> None:
        self.watch(self.app, "selected_entry_id", self.refresh)
