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
        height: 2;
        background: #999999;
        color: #000000;
        border: solid black;
        padding: 0 1;
        margin: 0;
    }
    """

    def render(self) -> str:
        app = self.app
        selected_id = app.selected_entry_id
        
        # Global Row - mockup format
        is_managed = False
        try:
            is_managed = len(getattr(app.services.get("vault")._manager, "profile_stack", [])) > 0
        except:
            pass
            
        exit_hint = "    [M]anaged Exit" if is_managed else ""
        global_row = (
            f"[b][S][/b]ettings    [b][A][/b]dd New Entry    "
            f"[b][C][/b]reate New Seed    [b][R][/b]emove Seed    "
            f"[b][E][/b]xport Data    [b][I][/b]mport Data    [b][B][/b]ackup Data{exit_hint}"
        )
        
        # Context Row (added from previous phase parity)
        if selected_id is None:
            context = "Select an entry to view actions."
        else:
            try:
                entry = app.services["entry"].retrieve_entry(selected_id)
                kind = str(entry.get("kind") or entry.get("type") or "").lower()
                
                actions = ["[b][v][/b] Reveal", "[b][g][/b] QR", "[b][e][/b] Edit", "[b][a][/b] Archive", "[b][c][/b] Copy", "[b][z][/b] Maximize"]
                if kind in {"managed_account", "seed"}:
                    actions.insert(4, "[b][m][/b] Load")
                if kind in {"document", "note"}:
                    actions.insert(5, "[b][x][/b] Export")
                    
                context = f"   Context ({kind}): " + " ▣ ".join(actions)
            except Exception:
                context = f"   Error fetching context details for Entry #{selected_id}"
            
        return f"{global_row}\n{context}"

    def on_mount(self) -> None:
        self.watch(self.app, "selected_entry_id", self.refresh)
        self.watch(self.app, "active_fingerprint", self.refresh)
