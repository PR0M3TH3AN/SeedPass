from __future__ import annotations
import time
from typing import Any, Callable

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.reactive import reactive
from textual.screen import Screen
from textual.widgets import Header, Footer, Static
from textual.containers import Horizontal, Vertical

from .widgets.header import RibbonHeader
from .widgets.sidebar import SidebarContainer
from .widgets.grid import GridContainer
from .widgets.inspector import BoardContainer
from .widgets.palette import CommandPalette
from .screens.settings import SettingsScreen
from .screens.inspector import MaximizedInspectorScreen

class CommandProcessor:
    """Handles logic for palette commands in TUI v3."""
    def __init__(self, app: SeedPassTuiV3):
        self.app = app

    def execute(self, raw: str) -> None:
        import shlex
        try:
            parts = shlex.split(raw)
        except Exception as e:
            self.app.notify(f"Parse error: {e}", severity="error")
            return
        
        if not parts: return
        cmd = parts[0].lower()
        args = parts[1:]

        if cmd == "help":
            self.app.notify("v3 commands: stats, lock, refresh, settings, maximize")
        elif cmd == "stats":
            self.app.notify("Calculating stats...")
            # We reuse the existing stats logic
            if "vault" in self.app.services:
                stats = self.app.services["vault"].stats()
                self.app.notify(f"Total entries: {stats.get('total_entries', 0)}")
        elif cmd == "lock":
            if "vault" in self.app.services:
                self.app.services["vault"].lock()
                self.app.session_locked = True
                self.app.notify("Vault locked")
        elif cmd == "refresh":
            self.app.action_refresh()
        elif cmd == "search":
            query = " ".join(args)
            self.app.action_search(query)
        elif cmd == "open":
            if not args:
                self.app.notify("Usage: open <id>", severity="warning")
                return
            try:
                eid = int(args[0])
                self.app.selected_entry_id = eid
                self.app.notify(f"Opened Entry #{eid}")
            except ValueError:
                self.app.notify("Entry ID must be an integer", severity="error")
        elif cmd == "settings":
            self.app.action_toggle_settings()
        elif cmd == "maximize":
            self.app.action_maximize_inspector()
        else:
            self.app.notify(f"Unknown v3 command: {cmd}", severity="warning")

class MainScreen(Screen):
    def compose(self) -> ComposeResult:
        yield CommandPalette(id="palette")
        yield Static("SeedPass ◈ UI v3", id="brand-strip")
        yield RibbonHeader(id="top-ribbon")
        with Vertical(id="body"):
            with Horizontal(id="top-work"):
                yield SidebarContainer(id="left")
                with Vertical(id="center"):
                    yield GridContainer(id="grid-work")
            with Vertical(id="right"):
                yield Static("Inspector Board", id="inspector-heading")
                yield BoardContainer(id="board-container")
        yield Static("Ready", id="status")
        yield Footer()

class SeedPassTuiV3(App[None]):
    """
    SeedPass TUI v3 - Rebuilt from scratch for modularity and mockup fidelity.
    """
    CSS = """
    #brand-strip {
        background: #0b0f13;
        color: #58f29d;
        text-style: bold;
        border: solid #2abf75;
        margin: 0 1;
        padding: 0 1;
        height: 3;
        content-align: center middle;
    }
    #body { height: 1fr; margin: 0 1; }
    #top-work { height: 6fr; }
    #left { width: 31; border: solid #1a3024; background: #0d1114; }
    #center { width: 1fr; border: solid #1a3024; background: #0d1114; margin-left: 1; }
    #right { height: 5fr; border: heavy #3ce79c; background: #0d1114; margin-top: 1; }
    #status {
        height: 3;
        padding: 0 1;
        border: heavy #58f29d;
        background: #11191f;
        color: #e4fff2;
        margin: 0 1;
    }
    #sidebar-placeholder, #grid-placeholder, #inspector-placeholder {
        height: 1fr;
        content-align: center middle;
        color: #3ce79c;
    }
    """
    
    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("ctrl+p", "open_palette", "Palette", show=True),
        Binding("shift+s", "toggle_settings", "Settings", show=True),
        Binding("z", "maximize_inspector", "Maximize", show=True),
    ]

    # Shared Reactive State
    active_fingerprint = reactive("")
    selected_entry_id = reactive[int | None](None)
    session_locked = reactive(True)

    def __init__(
        self,
        fingerprint: str | None = None,
        entry_service_factory: Callable | None = None,
        profile_service_factory: Callable | None = None,
        config_service_factory: Callable | None = None,
        nostr_service_factory: Callable | None = None,
        sync_service_factory: Callable | None = None,
        utility_service_factory: Callable | None = None,
        vault_service_factory: Callable | None = None,
        semantic_service_factory: Callable | None = None,
    ) -> None:
        super().__init__()
        # Store factories
        self.factories = {
            "entry": entry_service_factory,
            "profile": profile_service_factory,
            "config": config_service_factory,
            "nostr": nostr_service_factory,
            "sync": sync_service_factory,
            "utility": utility_service_factory,
            "vault": vault_service_factory,
            "semantic": semantic_service_factory,
        }
        # Initialized services
        self.services: dict[str, Any] = {}
        self._initial_fingerprint = fingerprint

    def on_mount(self) -> None:
        """Initialize services and push the main screen."""
        self.processor = CommandProcessor(self)
        for name, factory in self.factories.items():
            if factory:
                try:
                    self.services[name] = factory()
                except Exception as e:
                    self.log(f"Failed to init service {name}: {e}")
        
        self.active_fingerprint = self._initial_fingerprint or ""
        self.push_screen(MainScreen())
        # Global UI Heartbeat (for 2FA ticking etc)
        self.set_interval(1.0, self.action_refresh_ui_quiet)

    def on_command_palette_command_executed(self, message: CommandPalette.CommandExecuted) -> None:
        """Handle command from palette."""
        self.processor.execute(message.command)

    def action_refresh_ui_quiet(self) -> None:
        """Background refresh for dynamic elements (2FA)."""
        try:
            # We only refresh the inspector if it's currently showing a 2FA board
            board = self.query_one("#board-container")
            if board and hasattr(board, "children") and board.children:
                current_board = board.children[0]
                if current_board.__class__.__name__ == "TotpBoard":
                    current_board.refresh()
        except Exception:
            pass

    def watch_active_fingerprint(self, old_fp: str, new_fp: str) -> None:
        """Refresh components when the profile changes."""
        if not new_fp:
            return
        # Notify sidebar and grid to refresh
        try:
            self.query_one("#profile-tree")._refresh_tree()
            self.query_one("#entry-data-table")._refresh_data()
        except Exception:
            pass

    def watch_selected_entry_id(self, old_id: int | None, new_id: int | None) -> None:
        """Update inspectors when an entry is selected."""
        try:
            self.query_one("#board-container").update_entry(new_id)
        except Exception:
            pass

    def action_refresh(self) -> None:
        """Force a global UI refresh."""
        self.query_one("#profile-tree")._refresh_tree()
        self.query_one("#entry-data-table")._refresh_data()
        self.notify("UI Refreshed")

    def action_search(self, query: str) -> None:
        """Search entries and update grid."""
        try:
            self.query_one("#entry-data-table")._refresh_data(query)
            self.notify(f"Search results for: {query}")
        except Exception:
            pass

    def action_open_palette(self) -> None:
        """Toggle the command palette."""
        try:
            self.query_one("#palette").toggle()
        except Exception:
            pass

    def action_toggle_settings(self) -> None:
        """Push the full-screen settings screen."""
        self.push_screen(SettingsScreen())

    def action_maximize_inspector(self) -> None:
        """Push the full-screen maximized entry detail screen."""
        if self.selected_entry_id is None:
            self.notify("Select an entry to maximize", severity="warning")
            return
        self.push_screen(MaximizedInspectorScreen())
