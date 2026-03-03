from __future__ import annotations
from typing import Any
from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Static, Footer
from textual.containers import Vertical

class SettingsScreen(Screen):
    """
    A dedicated, full-screen settings management interface.
    Categorizes configuration into Security, Storage, and Connectivity.
    """
    
    BINDINGS = [
        ("escape", "app.pop_screen", "Back to Vault"),
        ("r", "refresh", "Refresh Settings"),
    ]

    DEFAULT_CSS = """
    SettingsScreen {
        background: #080a0c;
    }
    #settings-title {
        background: #0b0f13;
        color: #58f29d;
        text-style: bold;
        text-align: center;
        height: 3;
        border: double #2abf75;
        padding: 0 1;
        margin: 1 2;
    }
    #settings-container {
        height: 1fr;
        margin: 0 2;
        border: solid #1a3024;
        padding: 1;
        overflow: auto;
    }
    #settings-footer {
        height: 3;
        background: #11191f;
        color: #daf2e5;
        text-align: center;
        border: double #2abf75;
        padding: 0 1;
        margin: 1 2;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static("SeedPass ◈ System Configuration", id="settings-title")
        with Vertical(id="settings-container"):
            yield Static("Loading configuration...", id="settings-content")
        yield Static("ESC: Exit Settings | R: Reload | Use Palette (Ctrl+P) to change values", id="settings-footer")

    def on_mount(self) -> None:
        self.action_refresh()

    def action_refresh(self) -> None:
        """Fetch live settings and render them into the content panel."""
        app = self.app
        if "config" not in app.services:
            self.query_one("#settings-content", Static).update("[red]Config Service Offline[/red]")
            return

        service = app.services["config"]
        
        def get_val(key, default=""):
            try:
                val = service.get(key)
                return val if val is not None else default
            except Exception:
                return "[red](error)[/red]"

        # Categorized Rows
        security_rows = [
            f"Secret Mode    : {get_val('secret_mode_enabled', False)}  [dim](setting-secret on|off)[/dim]",
            f"Quick Unlock   : {get_val('quick_unlock', False)}  [dim](setting-quick-unlock on|off)[/dim]",
            f"KDF Iterations : {get_val('kdf_iterations', 100000)}  [dim](setting-kdf-iterations <n>)[/dim]",
            f"KDF Mode       : {get_val('kdf_mode', 'argon2id')}  [dim](setting-kdf-mode <mode>)[/dim]",
            f"Lock Timeout   : {get_val('inactivity_timeout', 300)}s  [dim](setting-timeout <s>)[/dim]",
        ]
        
        backup_rows = [
            f"Backup Path    : {get_val('additional_backup_path', '(none)')}  [dim](db-export <path>)[/dim]",
            f"Backup Interval: {get_val('backup_interval', 3600)}s",
        ]

        nostr_rows = [
            f"Sync Mode      : {get_val('semantic_search_mode', 'keyword')}  [dim](search-mode ...)[/dim]",
            f"Relays         : {len(get_val('relays', []))} connected  [dim](relay-list)[/dim]",
        ]

        # Use the app's card rendering utility if available, or fallback
        # In v3, we keep card logic in a central place or widget.
        # For now, we'll implement a clean local version.
        def render_card(title: str, rows: list[str]) -> str:
            width = 60
            top = f"┌─ {title} " + "─" * (width - len(title) - 4) + "┐"
            lines = [top]
            for row in rows:
                lines.append(f"│ {row:<{width-4}} │")
            lines.append("└" + "─" * (width - 2) + "┘")
            return "\n".join(lines)

        rendered_lines = [
            render_card("SECURITY & AUTHENTICATION", security_rows),
            "",
            render_card("STORAGE & BACKUP POLICY", backup_rows),
            "",
            render_card("CONNECTIVITY & NOSTR SYNC", nostr_rows),
        ]
        
        self.query_one("#settings-content", Static).update("\n".join(rendered_lines))
        self.app.notify("Settings reloaded")
