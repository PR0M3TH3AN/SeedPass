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
        height: 3;
        background: #10181f;
        color: #daf2e5;
        border: heavy #2abf75;
        padding: 0 1;
        margin: 0 1;
        text-style: bold;
    }
    """

    def render(self) -> str:
        app = self.app
        fp = app.active_fingerprint or "No Profile"
        lock_icon = "🔒" if app.session_locked else "🔓"
        status = "LOCKED" if app.session_locked else "UNLOCKED"
        
        # In a real app, we'd fetch stats from the service. 
        # For the shell, we'll use placeholders that look like the mockup.
        stats = "Entries: 0 | PWD: 0 | 2FA: 0 | Keys: 0"
        sync = "Sync: Never"
        
        # Layout: [Icon] Status | Fingerprint | Stats | Sync
        left = f"{lock_icon} {status} | Seed: {fp}"
        right = f"{stats} | {sync}"
        
        # Calculate spacing to push sync to the right
        available_width = self.size.width - len(left) - len(right) - 4
        spacer = " " * max(1, available_width)
        
        return f"{left}{spacer}{right}"

    def on_mount(self) -> None:
        # Refresh the header whenever important app state changes
        self.watch(self.app, "active_fingerprint", self.refresh)
        self.watch(self.app, "session_locked", self.refresh)
