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
from .widgets.action_bar import ActionBar
from .screens.settings import SettingsScreen
from .screens.inspector import MaximizedInspectorScreen
from .screens.relays import RelaysScreen


def render_qr_ascii(data: str) -> str:
    """Render ``data`` as an ASCII QR code."""
    import qrcode

    qr = qrcode.QRCode(border=1)
    qr.add_data(data)
    qr.make(fit=True)
    matrix = qr.get_matrix()
    lines: list[str] = []
    for row in matrix:
        lines.append("".join("##" if cell else "  " for cell in row))
    return "\n".join(lines)


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
            self.app.notify(
                "v3 commands: help, stats, session-status, lock, unlock <password>, refresh, search <query>, search-mode <keyword|hybrid|semantic>, filter <all|secrets|docs|keys|2fa>, archived, open <id>, settings, relay-list, maximize, copy, edit, export, add, seed-plus, archive, restore, ml, mx"
            )
        elif cmd == "stats":
            self.app.notify("Calculating stats...")
            # We reuse the existing stats logic
            if "vault" in self.app.services:
                stats = self.app.services["vault"].stats()
                self.app.notify(f"Total entries: {stats.get('total_entries', 0)}")
        elif cmd == "session-status":
            self.app.action_session_status()
        elif cmd == "lock":
            self.app.action_lock()
        elif cmd == "unlock":
            if len(args) != 1:
                self.app.notify("Usage: unlock <password>", severity="warning")
                return
            self.app.action_unlock(args[0])
        elif cmd == "refresh":
            self.app.action_refresh()
        elif cmd == "search":
            query = " ".join(args)
            self.app.action_search(query)
        elif cmd == "search-mode":
            if not args:
                self.app.notify("Usage: search-mode <keyword|hybrid|semantic>", severity="warning")
                return
            mode = args[0].lower()
            if mode in {"keyword", "hybrid", "semantic"}:
                self.app.search_mode = mode
                self.app.notify(f"Search mode set to: {mode}")
            else:
                self.app.notify(f"Invalid search mode: {mode}", severity="error")
        elif cmd == "filter":
            if not args:
                self.app.notify("Usage: filter <all|secrets|docs|keys|2fa>", severity="warning")
                return
            self.app.action_set_kind_filter(args[0])
        elif cmd == "archived":
            self.app.action_toggle_archived_view()
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
        elif cmd == "relay-list":
            self.app.action_toggle_relays()
        elif cmd == "maximize":
            self.app.action_maximize_inspector()
        elif cmd == "add":
            self.app.action_add_entry()
        elif cmd == "seed-plus":
            self.app.action_seed_plus()
        elif cmd == "copy":
            self.app.action_copy_selected()
        elif cmd == "edit":
            self.app.action_edit_selected()
        elif cmd == "export":
            self.app.action_export_selected()
        elif cmd == "ml":
            self.app.action_managed_load()
        elif cmd == "mx":
            self.app.action_managed_exit()
        elif cmd in {"archive", "restore"}:
            self.app.action_toggle_archive()
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
        Binding("shift+a", "add_entry", "Add", show=True),
        Binding("shift+c", "seed_plus", "Seed+", show=True),
        Binding("z", "maximize_inspector", "Maximize", show=True),
        Binding("m", "managed_load", "Load", show=True),
        Binding("shift+m", "managed_exit", "Exit", show=True),
        Binding("e", "edit_selected", "Edit", show=True),
        Binding("x", "export_selected", "Export", show=True),
        Binding("v", "reveal_selected", "Reveal", show=False),
        Binding("g", "show_qr", "QR", show=False),
        Binding("a", "toggle_archive", "Archive", show=False),
        Binding("c", "copy_selected", "Copy", show=False),
    ]

    # Shared Reactive State
    active_fingerprint = reactive("")
    selected_entry_id = reactive[int | None](None)
    session_locked = reactive(False)
    search_mode = reactive("keyword")
    filter_kind = reactive("all")
    show_archived = reactive(False)

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
            board = self.screen.query_one("#board-container")
            if board and hasattr(board, "children") and board.children:
                current_board = board.children[0]
                # Ensure selection/inspector stay synchronized if a selection is set
                # but the board is still idle after screen transitions.
                if (
                    self.selected_entry_id is not None
                    and current_board.__class__.__name__ == "IdleBoard"
                ):
                    board.update_entry(self.selected_entry_id)
                    return
                # Refresh dynamic TOTP countdown only for the active TOTP board.
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
            self.screen.query_one("#profile-tree")._refresh_tree()
            self.screen.query_one("#entry-data-table")._refresh_data()
        except Exception:
            pass

    def watch_selected_entry_id(self, old_id: int | None, new_id: int | None) -> None:
        """Update inspectors when an entry is selected."""
        try:
            self.screen.query_one("#board-container").update_entry(new_id)
        except Exception:
            pass

    def action_refresh(self) -> None:
        """Force a global UI refresh."""
        self.screen.query_one("#profile-tree")._refresh_tree()
        self.screen.query_one("#entry-data-table")._refresh_data()
        self.notify("UI Refreshed")

    def action_search(self, query: str) -> None:
        """Search entries and update grid."""
        try:
            self.screen.query_one("#entry-data-table")._refresh_data(query)
            self.notify(f"Search results for: {query}")
        except Exception:
            pass

    def action_toggle_archived_view(self) -> None:
        """Toggle between active entries and archived entries."""
        self.show_archived = not self.show_archived
        self.notify(f"Showing archived entries: {self.show_archived}")
        self.action_refresh()

    def action_set_kind_filter(self, kind: str) -> None:
        """Set a specific entry kind filter (all, secrets, docs, keys, 2fa)."""
        self.filter_kind = kind.lower()
        self.notify(f"Applied filter: {self.filter_kind}")
        self.action_refresh()

    def action_open_palette(self) -> None:
        """Toggle the command palette."""
        try:
            self.screen.query_one("#palette").toggle()
        except Exception:
            pass

    def action_toggle_settings(self) -> None:
        """Push the full-screen settings screen."""
        self.push_screen(SettingsScreen())

    def action_toggle_relays(self) -> None:
        """Push the Nostr Relay Management screen."""
        self.push_screen(RelaysScreen())

    def action_add_entry(self) -> None:
        """Open the add entry wizard."""
        if self.session_locked:
            self.notify("Vault is locked", severity="error")
            return
        from .screens.add import AddEntryScreen
        self.push_screen(AddEntryScreen())

    def action_seed_plus(self) -> None:
        """Open the Seed+ / BIP-85 derivation screen."""
        if self.session_locked:
            self.notify("Vault is locked", severity="error")
            return
        from .screens.add import SeedPlusScreen
        self.push_screen(SeedPlusScreen())

    def action_maximize_inspector(self) -> None:
        """Push the full-screen maximized entry detail screen."""
        if self.selected_entry_id is None:
            self.notify("Select an entry to maximize", severity="warning")
            return
        self.push_screen(MaximizedInspectorScreen())

    def action_session_status(self) -> None:
        """Display vault lock status."""
        state = "locked" if self.session_locked else "unlocked"
        self.notify(f"Session status: {state}")

    def action_lock(self) -> None:
        """Lock the vault if service support is available."""
        vault = self.services.get("vault")
        if vault is None:
            self.notify("Vault service unavailable", severity="error")
            return
        locker = getattr(vault, "lock", None)
        if not callable(locker):
            self.notify("Vault service does not support lock", severity="error")
            return
        try:
            locker()
            self.session_locked = True
            self.notify("Vault locked")
        except Exception as e:
            self.notify(f"Lock failed: {e}", severity="error")

    def action_unlock(self, password: str) -> None:
        """Unlock the vault with a password."""
        vault = self.services.get("vault")
        if vault is None:
            self.notify("Vault service unavailable", severity="error")
            return
        unlocker = getattr(vault, "unlock", None)
        if not callable(unlocker):
            self.notify("Vault service does not support unlock", severity="error")
            return
        try:
            try:
                from seedpass.core.api import UnlockRequest

                unlocker(UnlockRequest(password=password))
            except Exception:
                unlocker(password)
            self.session_locked = False
            self.notify("Vault unlocked")
        except Exception as e:
            self.notify(f"Unlock failed: {e}", severity="error")

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
        """Toggle archived status for selected entry."""
        if self.session_locked:
            self.notify("Vault is locked", severity="error")
            return
        if self.selected_entry_id is None:
            return
        
        try:
            entry = self.services["entry"].retrieve_entry(self.selected_entry_id)
            is_archived = entry.get("archived", False)
            
            if is_archived:
                self.services["entry"].restore_entry(self.selected_entry_id)
                self.notify(f"Restored Entry #{self.selected_entry_id}")
            else:
                self.services["entry"].archive_entry(self.selected_entry_id)
                self.notify(f"Archived Entry #{self.selected_entry_id}")
            
            # Refresh UI
            self.action_refresh()
        except Exception as e:
            self.notify(f"Archive failed: {e}", severity="error")

    def action_copy_selected(self) -> None:
        """Copy the primary sensitive field of the selected entry to the clipboard."""
        if self.session_locked:
            self.notify("Vault is locked", severity="error")
            return
        if self.selected_entry_id is None:
            return

        try:
            payload = self._resolve_sensitive_payload()
            # payload is (title, body, qr_data, secret_value, kind)
            secret = payload[3]
            if secret:
                success = self.services["entry"].copy_to_clipboard(secret)
                if success:
                    self.notify(f"Copied {payload[4]} value to clipboard")
                else:
                    self.notify("Clipboard copy failed", severity="warning")
            else:
                self.notify("No value to copy", severity="warning")
        except Exception as e:
            self.notify(f"Copy failed: {e}", severity="error")

    def action_managed_load(self) -> None:
        """Load the selected managed account or seed profile as the active session."""
        if self.session_locked:
            self.notify("Vault is locked", severity="error")
            return
        if self.selected_entry_id is None:
            return
        
        try:
            entry = self.services["entry"].retrieve_entry(self.selected_entry_id)
            kind = str(entry.get("kind") or entry.get("type") or "").lower()
            if kind not in {"managed_account", "seed"}:
                self.notify("Selected entry is not a loadable profile", severity="warning")
                return
            
            self.services["entry"].load_managed_account(self.selected_entry_id)
            # Update reactive state to trigger UI refresh
            self.active_fingerprint = self.services["vault"]._manager.current_fingerprint
            self.notify(f"Loaded session: {self.active_fingerprint[:8]}...")
            self.action_refresh()
        except Exception as e:
            self.notify(f"Load failed: {e}", severity="error")

    def action_managed_exit(self) -> None:
        """Exit the current managed session and return to the parent profile."""
        try:
            self.services["entry"].exit_managed_account()
            # Update reactive state
            self.active_fingerprint = self.services["vault"]._manager.current_fingerprint
            self.notify(f"Exited session. Back to: {self.active_fingerprint[:8]}...")
            self.action_refresh()
        except Exception as e:
            self.notify(f"Exit failed: {e}", severity="error")

    def action_edit_selected(self) -> None:
        """Open the appropriate edit screen for the selected entry."""
        if self.session_locked:
            self.notify("Vault is locked", severity="error")
            return
        if self.selected_entry_id is None:
            return
        
        try:
            entry = self.services["entry"].retrieve_entry(self.selected_entry_id)
            kind = str(entry.get("kind") or entry.get("type") or "").lower()
            
            if kind in {"document", "note"}:
                from .screens.edit import DocumentEditScreen
                self.push_screen(DocumentEditScreen(self.selected_entry_id))
            else:
                self.notify(f"Edit mode for '{kind}' not yet implemented in v3", severity="warning")
        except Exception as e:
            self.notify(f"Edit failed: {e}", severity="error")

    def action_export_selected(self) -> None:
        """Export the selected entry to a file if supported."""
        if self.session_locked:
            self.notify("Vault is locked", severity="error")
            return
        if self.selected_entry_id is None:
            return

        try:
            entry = self.services["entry"].retrieve_entry(self.selected_entry_id)
            kind = str(entry.get("kind") or entry.get("type") or "").lower()

            if kind in {"document", "note"}:
                path = self.services["entry"].export_document_file(self.selected_entry_id)
                self.notify(f"Document exported to: {path}")
            elif kind in {"ssh", "pgp"}:
                # For SSH/PGP, we might want to export to a file too.
                # Currently EntryService doesn't have a direct file export for these,
                # but we could implement it.
                self.notify(f"Export for '{kind}' not yet implemented in v3", severity="warning")
            else:
                self.notify(f"Export not supported for kind '{kind}'", severity="warning")
        except Exception as e:
            self.notify(f"Export failed: {e}", severity="error")

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
            requires = kind in {"seed", "managed_account", "nostr"} # for nostr qr we often show nsec if mode is private
        else:
            requires = kind in {"seed", "managed_account", "ssh", "pgp", "nostr"}

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
            return ("Password Revealed", val, None, val, kind)
        if kind == "totp":
            secret = self.services["entry"].get_totp_secret(eid)
            from seedpass.core.totp import TotpManager
            uri = TotpManager.make_otpauth_uri(label, secret)
            return ("TOTP Secret Revealed", secret, uri, secret, kind)
        if kind in {"seed", "managed_account"}:
            parent_seed = self.services["vault"]._manager.parent_seed
            if kind == "seed":
                phrase = self.services["entry"].get_seed_phrase(eid, parent_seed)
            else:
                phrase = self.services["entry"].get_managed_account_seed(eid, parent_seed)
            from seedpass.core.seedqr import encode_seedqr
            return ("Seed Words Revealed", phrase, encode_seedqr(phrase), phrase, kind)
        
        if kind == "ssh":
            priv, pub = self.services["entry"].get_ssh_key_pair(eid)
            return ("SSH Private Key Revealed", priv, pub, pub, kind)
        
        if kind == "pgp":
            priv, pub, fp = self.services["entry"].get_pgp_key(eid)
            return ("PGP Private Key Revealed", priv, pub, pub, kind)
        
        if kind == "nostr":
            npub, nsec = self.services["entry"].get_nostr_key_pair(eid)
            qr_data = nsec if qr_mode == "private" else f"nostr:{npub}"
            return ("Nostr Secret Revealed", nsec, qr_data, nsec, kind)
        
        if kind == "key_value":
            val = entry.get("value", "")
            return ("Key-Value Revealed", val, None, val, kind)
        
        if kind in {"document", "note"}:
            content = entry.get("content", "")
            return ("Document Content", content, None, content, kind)

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
            board_cont = self.screen.query_one("#board-container")
            if board_cont.children:
                board = board_cont.children[0]
                if hasattr(board, "reveal_data"):
                    board.reveal_data = data
        except Exception:
            pass
