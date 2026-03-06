from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.screen import Screen
from textual.widgets import Button, Input, Label, Static

from .maintenance import MAINTENANCE_CSS, format_status


class ChangePasswordScreen(Screen):
    """Dedicated flow for changing the active vault password."""

    BINDINGS = [
        Binding("ctrl+s", "submit", "Submit", show=True),
        Binding("escape", "app.pop_screen", "Cancel", show=True),
    ]

    CSS = (
        MAINTENANCE_CSS
        + """
    ChangePasswordScreen {
        background: #999999;
    }
    #change-password-container {
        height: auto;
        min-height: 18;
    }
    #change-password-actions Button {
        min-width: 18;
    }
    """
    )

    def compose(self) -> ComposeResult:
        yield Static("SeedPass ◈ Change Vault Password", classes="maintenance-title")
        with Container(id="change-password-container", classes="maintenance-panel-dark"):
            yield Static(
                "Change the vault password for the active profile. You must provide the current password to authorize re-encryption.",
                id="change-password-intro",
                classes="maintenance-intro-dark",
            )
            yield Label("Current Password", classes="maintenance-label")
            yield Input(password=True, id="change-password-old", classes="maintenance-input")
            yield Label("New Password", classes="maintenance-label")
            yield Input(password=True, id="change-password-new", classes="maintenance-input")
            yield Label("Confirm New Password", classes="maintenance-label")
            yield Input(password=True, id="change-password-confirm", classes="maintenance-input")
            yield Static(
                format_status("ready", "Enter the current and new password to continue."),
                id="change-password-status",
                classes="maintenance-status-dark",
            )
            with Horizontal(id="change-password-actions", classes="maintenance-actions"):
                yield Button("Cancel", id="change-password-cancel", classes="maintenance-danger")
                yield Button("Update Password", id="change-password-submit", classes="maintenance-primary")
        yield Static("ESC: Cancel | Ctrl+S: Submit", classes="maintenance-footer")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "change-password-submit":
            self.action_submit()
        else:
            self.app.pop_screen()

    def _set_status(self, message: str) -> None:
        self.query_one("#change-password-status", Static).update(message)

    def action_submit(self) -> None:
        old_password = self.query_one("#change-password-old", Input).value
        new_password = self.query_one("#change-password-new", Input).value
        confirm = self.query_one("#change-password-confirm", Input).value

        if not old_password or not new_password:
            self._set_status(format_status("warning", "Current and new passwords are required."))
            return
        if new_password != confirm:
            self._set_status(format_status("warning", "New password confirmation does not match."))
            return
        self.app.action_change_password(old_password, new_password)


class BackupParentSeedScreen(Screen):
    """Dedicated flow for encrypted parent-seed backup export."""

    BINDINGS = [
        Binding("ctrl+s", "submit", "Submit", show=True),
        Binding("escape", "app.pop_screen", "Cancel", show=True),
    ]

    CSS = (
        MAINTENANCE_CSS
        + """
    BackupParentSeedScreen {
        background: #999999;
    }
    #backup-seed-container {
        height: auto;
        min-height: 18;
    }
    #backup-seed-actions Button {
        min-width: 18;
    }
    """
    )

    def compose(self) -> ComposeResult:
        yield Static("SeedPass ◈ Backup Parent Seed", classes="maintenance-title")
        with Container(id="backup-seed-container", classes="maintenance-panel-dark"):
            yield Static(
                "Export an encrypted copy of the parent seed. Choose a destination path and an optional backup password. Store both securely.",
                id="backup-seed-intro",
                classes="maintenance-intro-dark",
            )
            yield Label("Destination Path", classes="maintenance-label")
            yield Input(placeholder="seed-backup.enc", id="backup-seed-path", classes="maintenance-input")
            yield Label("Backup Password (optional)", classes="maintenance-label")
            yield Input(password=True, id="backup-seed-password", classes="maintenance-input")
            yield Static(
                format_status("ready", "Enter the backup destination path to export an encrypted seed bundle."),
                id="backup-seed-status",
                classes="maintenance-status-dark",
            )
            with Horizontal(id="backup-seed-actions", classes="maintenance-actions"):
                yield Button("Cancel", id="backup-seed-cancel", classes="maintenance-danger")
                yield Button("Export Backup", id="backup-seed-submit", classes="maintenance-primary")
        yield Static("ESC: Cancel | Ctrl+S: Submit", classes="maintenance-footer")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "backup-seed-submit":
            self.action_submit()
        else:
            self.app.pop_screen()

    def _set_status(self, message: str) -> None:
        self.query_one("#backup-seed-status", Static).update(message)

    def action_submit(self) -> None:
        path = self.query_one("#backup-seed-path", Input).value.strip()
        password = self.query_one("#backup-seed-password", Input).value
        if not path:
            self._set_status(format_status("warning", "Destination path is required."))
            return
        self.app.action_backup_parent_seed(path, password or None)
