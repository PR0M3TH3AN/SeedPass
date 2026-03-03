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
        height: auto;
        min-height: 4;
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
            
        exit_hint = "    [@click='app.managed_exit'][b][M][/b]anaged Exit[/]" if is_managed else ""
        global_row = (
            f"[@click='app.toggle_settings'][b][S][/b]ettings[/]    [@click='app.add_entry'][b][A][/b]dd New Entry[/]    "
            f"[@click='app.seed_plus'][b][C][/b]reate New Seed[/]    "
            f"[@click='app.open_palette'][b][R][/b]emove Seed[/]    "
            f"[@click='app.action_db_export'][b][E][/b]xport Data[/]    [@click='app.action_db_import'][b][I][/b]mport Data[/]    [@click='app.open_palette'][b][B][/b]ackup Data[/]{exit_hint}"
        )
        
        # Context Row (added from previous phase parity)
        if selected_id is None:
            context = "Select an entry to view actions."
        else:
            try:
                entry = app.services["entry"].retrieve_entry(selected_id)
                kind = str(entry.get("kind") or entry.get("type") or "").lower()
                
                actions = [
                    "[@click='app.reveal_selected'][b][v][/b] Reveal[/]", 
                    "[@click='app.show_qr'][b][g][/b] QR[/]", 
                    "[@click='app.edit_selected'][b][e][/b] Edit[/]", 
                    "[@click='app.toggle_archive'][b][a][/b] Archive[/]", 
                    "[@click='app.copy_selected'][b][c][/b] Copy[/]", 
                    "[@click='app.maximize_inspector'][b][z][/b] Maximize[/]"
                ]
                if kind in {"managed_account", "seed"}:
                    actions.insert(4, "[@click='app.managed_load'][b][m][/b] Load[/]")
                if kind in {"document", "note"}:
                    actions.insert(5, "[@click='app.export_selected'][b][x][/b] Export[/]")
                    
                context = f"   Context ({kind}): " + " ▣ ".join(actions)
            except Exception:
                context = f"   Error fetching context details for Entry #{selected_id}"
            
        return f"{global_row}\n{context}"

    def on_mount(self) -> None:
        self.watch(self.app, "selected_entry_id", self.refresh)
        self.watch(self.app, "active_fingerprint", self.refresh)
