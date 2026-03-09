from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Input, Label, Static

from .maintenance import MAINTENANCE_CSS, format_status


class ProfileManagementScreen(Screen):
    """Manage profile switching and removal inside TUI v3."""

    def __init__(self) -> None:
        super().__init__()
        self._pending_remove_fingerprint: str | None = None

    BINDINGS = [
        Binding("ctrl+r", "refresh_profiles", "Refresh", show=True),
        Binding("escape", "app.pop_screen", "Back", show=True),
    ]

    CSS = (
        MAINTENANCE_CSS
        + """
    ProfileManagementScreen {
        background: #999999;
    }
    #profile-container {
        height: auto;
        min-height: 20;
    }
    #profile-list {
        border: solid #666666;
        margin-top: 1;
        min-height: 8;
    }
    #profile-actions Button {
        min-width: 14;
    }
    """
    )

    def compose(self) -> ComposeResult:
        yield Static("SeedPass ◈ Profile Management", classes="maintenance-title")
        with Container(id="profile-container", classes="maintenance-panel-dark"):
            yield Static(
                "Switch between profiles or remove unused ones. The active profile is marked with ►. Each profile is identified by its fingerprint. Removing a profile is permanent and requires confirmation.",
                id="profile-intro",
                classes="maintenance-intro-dark",
            )
            yield Static("", id="profile-list", classes="maintenance-intro-dark")
            yield Label("Select Profile", classes="maintenance-label")
            yield Input(placeholder="Profile number", id="profile-choice", classes="maintenance-input")
            yield Label("Password (required for switch)", classes="maintenance-label")
            yield Input(password=True, id="profile-password", classes="maintenance-input")
            yield Static(
                format_status("ready", "Choose a profile number, then use Switch or Remove."),
                id="profile-status",
                classes="maintenance-status-dark",
            )
            with Horizontal(id="profile-actions", classes="maintenance-actions"):
                yield Button("Switch", id="profile-switch", classes="maintenance-primary")
                yield Button("Remove", id="profile-remove", classes="maintenance-danger")
                yield Button("Back", id="profile-back", classes="maintenance-secondary")
        yield Static(
            "ESC: Back | Ctrl+R: Refresh | Select a profile number to switch or remove",
            classes="maintenance-footer",
        )

    def on_mount(self) -> None:
        self.action_refresh_profiles()

    def action_refresh_profiles(self) -> None:
        self._pending_remove_fingerprint = None
        self._render_profiles()

    def _available_profiles(self) -> list[dict[str, str]]:
        service = self.app.services.get("profile")
        if not service:
            return []
        raw_profiles = list(service.list_profiles())
        display_map = {
            item.get("fingerprint", ""): item.get("label", item.get("fingerprint", ""))
            for item in self.app._list_boot_profiles()
        }
        out: list[dict[str, str]] = []
        for fingerprint in raw_profiles:
            out.append(
                {
                    "fingerprint": fingerprint,
                    "label": display_map.get(fingerprint, fingerprint),
                }
            )
        return out

    def _render_profiles(self) -> None:
        if "profile" not in self.app.services:
            self.query_one("#profile-list", Static).update("Profile service offline.")
            return
        current = self.app.active_fingerprint
        profiles = self._available_profiles()
        lines = ["Profiles"]
        for idx, profile in enumerate(profiles, start=1):
            fingerprint = profile["fingerprint"]
            label = profile["label"]
            marker = "►" if fingerprint == current else " "
            lines.append(f"{idx}. {marker} {label}")
        if not profiles:
            lines.append("(none)")
        self.query_one("#profile-list", Static).update("\n".join(lines))
        if profiles:
            self.query_one("#profile-choice", Input).value = "1"
            self._set_status(
                format_status("ready", "Choose a profile number, then use Switch or Remove.")
            )

    def _selected_profile(self) -> dict[str, str] | None:
        profiles = self._available_profiles()
        choice = self.query_one("#profile-choice", Input).value.strip()
        if not choice.isdigit():
            self._set_status(format_status("warning", "Enter a valid profile number."))
            return None
        idx = int(choice)
        if idx < 1 or idx > len(profiles):
            self._set_status(format_status("warning", "Profile number is out of range."))
            return None
        return profiles[idx - 1]

    def _set_status(self, message: str) -> None:
        self.query_one("#profile-status", Static).update(message)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        if button_id == "profile-back":
            self.app.pop_screen()
            return
        if button_id == "profile-switch":
            self._pending_remove_fingerprint = None
            selected = self._selected_profile()
            if selected is not None:
                self._set_status(
                    format_status(
                        "working", f"Switching to profile '{selected['label']}'..."
                    )
                )
            self.app.action_switch_profile(
                None if selected is None else selected["fingerprint"],
                self.query_one("#profile-password", Input).value or None,
            )
            return
        if button_id == "profile-remove":
            selected = self._selected_profile()
            if selected is None:
                return
            fingerprint = selected["fingerprint"]
            label = selected["label"]
            if self._pending_remove_fingerprint != fingerprint:
                self._pending_remove_fingerprint = fingerprint
                self._set_status(
                    format_status(
                        "warning", f"Confirm: press Remove again to permanently delete profile '{label}'."
                    )
                )
                return
            self._pending_remove_fingerprint = None
            self.app.action_remove_profile(fingerprint)
