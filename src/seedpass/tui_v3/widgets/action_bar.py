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
        is_managed = False
        try:
            is_managed = len(getattr(app.services.get("vault")._manager, "profile_stack", [])) > 0
        except:
            pass
            
        exit_hint = "  Exit (Shift+M)" if is_managed else ""
        global_row = (
            f"Settings (Shift+S)  Add (Shift+A)  Seed+ (Shift+C)  "
            f"Backup (B)  Cmd (Ctrl+P){exit_hint}"
        )
        
        # Context Row
        if selected_id is None:
            context = "Select an entry to view actions."
        else:
            try:
                entry = app.services["entry"].retrieve_entry(selected_id)
                kind = str(entry.get("kind") or entry.get("type") or "").lower()
                
                actions = ["Reveal (v)", "QR (g)", "Edit (e)", "Archive (a)", "Copy (c)", "Max (z)"]
                if kind in {"managed_account", "seed"}:
                    actions.insert(4, "Load (m)")
                if kind in {"document", "note"}:
                    actions.insert(5, "Export (x)")
                    
                context = f"Entry #{selected_id} ({kind}) " + " ▣ ".join(actions)
            except Exception:
                context = f"Entry #{selected_id} [Error fetching details]"
            
        return f"{global_row}\n{context}"

    def on_mount(self) -> None:
        self.watch(self.app, "selected_entry_id", self.refresh)
        self.watch(self.app, "active_fingerprint", self.refresh)
