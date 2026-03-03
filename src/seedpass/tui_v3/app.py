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
        yield ActionBar(id="action-bar")
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
        Binding("v", "reveal_selected", "Reveal", show=False),
        Binding("g", "show_qr", "QR", show=False),
        Binding("a", "toggle_archive", "Archive", show=False),
        Binding("c", "copy_selected", "Copy", show=False),
    ]

    # Shared Reactive State
    active_fingerprint = reactive("")
    selected_entry_id = reactive[int | None](None)
    session_locked = reactive(True)

    # Internal state for sensitive actions
    _pending_sensitive_confirm: tuple[str, int, float] | None = None

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

    def action_reveal_selected(self, confirm: bool = False) -> None:
        """Handle reveal shortcut (v)."""
        if self.session_locked:
            self.notify("Vault is locked", severity="error")
            return
        if self.selected_entry_id is None:
            return
        
        # Check confirmation
        if not confirm:
            confirm = self._consume_confirm("reveal_selected", self.selected_entry_id)
            
        self._show_sensitive_view(include_qr=False, confirm=confirm)

    def action_show_qr(self, mode: str = "default", confirm: bool = False) -> None:
        """Handle QR shortcut (g)."""
        if self.session_locked:
            self.notify("Vault is locked", severity="error")
            return
        if self.selected_entry_id is None:
            return

        if not confirm:
            confirm = self._consume_confirm("show_qr", self.selected_entry_id)

        self._show_sensitive_view(include_qr=True, qr_mode=mode, confirm=confirm)

    def action_toggle_archive(self) -> None:
        self.notify("Archive toggle Coming Soon in V3")

    def action_copy_selected(self) -> None:
        self.notify("Copy Coming Soon in V3")

    def _consume_confirm(self, action: str, eid: int) -> bool:
        if self._pending_sensitive_confirm is None: return False
        p_action, p_eid, p_ts = self._pending_sensitive_confirm
        now = time.time()
        if p_action == action and p_eid == eid and (now - p_ts) <= 8.0:
            self._pending_sensitive_confirm = None
            return True
        self._pending_sensitive_confirm = None
        return False

    def _show_sensitive_view(self, include_qr: bool, qr_mode: str = "default", confirm: bool = False) -> None:
        try:
            payload = self._resolve_sensitive_payload(qr_mode=qr_mode)
            title, body, qr_data, secret, kind = payload
        except Exception as e:
            self.notify(f"Reveal failed: {e}", severity="error")
            return

        # Check if confirmation is required
        requires = False
        if include_qr:
            requires = (kind == "nostr" and qr_mode == "private")
        else:
            requires = kind in {"seed", "managed_account", "ssh", "pgp"}

        if requires and not confirm:
            key = "g" if include_qr else "v"
            self._pending_sensitive_confirm = ("show_qr" if include_qr else "reveal_selected", self.selected_entry_id, time.time())
            # Update the board with confirmation prompt
            self._update_board_sensitive(prompt=f"CONFIRMATION REQUIRED\n\nHigh-risk action for '{kind}'.\nPress '{key}' again within 8s to proceed.")
            self.notify(f"Press '{key}' again to confirm")
            return

        # Success - Update Board
        if include_qr:
            try:
                qr_rendered = render_qr_ascii(qr_data)
                self._update_board_sensitive(content=qr_rendered, title=title)
            except Exception as e:
                self.notify(f"QR Render failed: {e}", severity="error")
        else:
            self._update_board_sensitive(content=body, title=title)

    def _resolve_sensitive_payload(self, qr_mode="default"):
        if "entry" not in self.services: raise ValueError("Service offline")
        eid = self.selected_entry_id
        entry = self.services["entry"].retrieve_entry(eid)
        if not entry: raise ValueError("Entry not found")
        
        kind = str(entry.get("kind") or entry.get("type") or "").lower()
        label = entry.get("label", "")
        
        if kind == "password":
            val = self.services["entry"].generate_password(int(entry.get("length", 16)), eid)
            return ("Password Revealed", f"Label: {label}\nPassword: {val}", None, val, kind)
        if kind == "totp":
            secret = self.services["entry"].get_totp_secret(eid)
            from seedpass.core.totp import TotpManager
            uri = TotpManager.make_otpauth_uri(label, secret)
            return ("TOTP Secret Revealed", f"Label: {label}\nSecret: {secret}", uri, secret, kind)
        if kind in {"seed", "managed_account"}:
            parent_seed = self.services["vault"]._manager.parent_seed
            if kind == "seed":
                phrase = self.services["entry"].get_seed_phrase(eid, parent_seed)
            else:
                phrase = self.services["entry"].get_managed_account_seed(eid, parent_seed)
            from seedpass.core.seedqr import encode_seedqr
            return ("Seed Words Revealed", f"Label: {label}\nSeed: {phrase}", encode_seedqr(phrase), phrase, kind)
        
        # Fallback
        return ("Data Revealed", f"Label: {label}\nDetails: {entry}", None, None, kind)

    def _update_board_sensitive(self, content: str = None, title: str = None, prompt: str = None):
        """Push sensitive data to the currently active board or screen."""
        data = {"content": content, "title": title, "prompt": prompt}
        
        # 1. Update full-screen inspector if active
        if isinstance(self.screen, MaximizedInspectorScreen):
            self.screen.reveal_data = data
            return

        # 2. Update standard inspector board
        try:
            board_cont = self.query_one("#board-container")
            if board_cont.children:
                board = board_cont.children[0]
                if hasattr(board, "reveal_data"):
                    board.reveal_data = data
        except Exception:
            pass
