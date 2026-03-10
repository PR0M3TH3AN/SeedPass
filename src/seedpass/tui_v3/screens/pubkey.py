from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import Button, Static
from textual.containers import Horizontal, Vertical

from .maintenance import MAINTENANCE_CSS, format_status


class NostrPubkeyScreen(Screen):
    """Display the active profile npub and its public QR payload."""

    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back", show=True),
        Binding("c", "copy_pubkey", "Copy npub", show=True),
    ]

    CSS = (
        MAINTENANCE_CSS
        + """
    NostrPubkeyScreen {
        background: #999999;
    }
    #pubkey-container {
        height: 1fr;
    }
    #pubkey-content {
        border: solid #666666;
    }
    #pubkey-actions {
        align: right middle;
    }
    #pubkey-copy {
        min-width: 16;
    }
    """
    )

    def compose(self) -> ComposeResult:
        yield Static("SeedPass ◈ Active Profile npub", classes="maintenance-title")
        with Vertical(id="pubkey-container", classes="maintenance-panel-light"):
            yield Static(
                "Your active profile public Nostr identifier (npub). This is safe to share. Never share private keys.",
                id="pubkey-intro",
                classes="maintenance-intro-light",
            )
            yield Static(
                format_status("working", "Loading npub..."),
                id="pubkey-content",
                classes="maintenance-status-light",
            )
            with Horizontal(id="pubkey-actions", classes="maintenance-actions"):
                yield Button("Copy npub", id="pubkey-copy", classes="maintenance-primary")
        yield Static("ESC: Back | C: Copy npub to clipboard", classes="maintenance-footer")

    def on_mount(self) -> None:
        self._refresh_view()

    def _refresh_view(self) -> None:
        nostr = self.app.services.get("nostr")
        if not nostr:
            self.query_one("#pubkey-content", Static).update(
                format_status("error", "Nostr service offline.")
            )
            return
        try:
            npub = nostr.get_pubkey()
            qr = self.app.render_qr_ascii(f"nostr:{npub}")
            text = (
                f"{format_status('success', 'Active profile npub loaded.')}\n\n"
                f"[b]npub[/b]\n{npub}\n\n[b]Public QR[/b]\n{qr}"
            )
            self.query_one("#pubkey-content", Static).update(text)
        except Exception as e:
            self.query_one("#pubkey-content", Static).update(
                format_status("error", f"Failed to load npub: {e}")
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "pubkey-copy":
            self.action_copy_pubkey()

    def action_copy_pubkey(self) -> None:
        nostr = self.app.services.get("nostr")
        entry = self.app.services.get("entry")
        if not nostr or not entry:
            self.app.notify("Clipboard or Nostr service unavailable", severity="warning")
            return
        try:
            npub = nostr.get_pubkey()
            if entry.copy_to_clipboard(npub):
                self.app.notify("Copied npub to clipboard")
            else:
                self.app.notify("Clipboard copy failed", severity="warning")
        except Exception as e:
            self.app.notify(f"Copy failed: {e}", severity="error")
