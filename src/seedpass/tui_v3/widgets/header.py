from __future__ import annotations
from textual.app import ComposeResult
from textual.widgets import Static
from textual.reactive import reactive

class RibbonHeader(Static):
    """
    A high-density status ribbon that displays active profile, 
    session state, and vault metrics.
    
    Matches the 'UI Board' mockup top ribbon layout.
    """
    
    DEFAULT_CSS = """
    RibbonHeader {
        height: 1;
        background: #999999;
        color: #000000;
        padding: 0 1;
        margin: 0;
        text-style: bold;
    }
    """

    def render(self) -> str:
        app = self.app
        
        # Gather metrics from actual services
        managed = 0
        try:
            managed = len(getattr(app.services.get("vault")._manager, "profile_stack", []))
        except:
            pass
            
        entries = 0
        try:
            table = app.screen.query_one("#entry-data-table")
            if table:
                entries = len(table.rows)
        except:
            pass
            
        sync = "YYY-MM-DDThh:mm:ssTZD"
        
        # Build the exact string parts from the mockup
        left = f"Managed Users: {managed}       Entries: {entries}       ◀ ▶ Kind = {app.filter_kind.capitalize()}"
        right = f"Last Sync: {sync}"
        
        # Calculate spacing to push sync to the right edge
        available_width = self.size.width - len(left) - len(right) - 2
        spacer = " " * max(1, available_width)
        
        return f"{left}{spacer}{right}"

    def on_mount(self) -> None:
        # Refresh the header whenever important app state changes
        self.watch(self.app, "active_fingerprint", self.refresh)
        self.watch(self.app, "session_locked", self.refresh)
        self.watch(self.app, "filter_kind", self.refresh)
