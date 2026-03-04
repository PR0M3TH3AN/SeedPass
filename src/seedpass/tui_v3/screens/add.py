from __future__ import annotations
from typing import Any
from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import (
    Header,
    Footer,
    Input,
    Label,
    Button,
    Select,
    TextArea,
    Checkbox,
)
from textual.containers import Vertical, Horizontal, Container, Grid
from textual.binding import Binding
from seedpass.core.entry_types import EntryType


class AddEntryScreen(Screen):
    """
    A unified wizard-style screen for adding new entries.
    Supports selecting entry kind and filling relevant fields.
    """

    BINDINGS = [
        Binding("ctrl+s", "save", "Save", show=True),
        Binding("escape", "app.pop_screen", "Cancel", show=True),
    ]

    CSS = """
    AddEntryScreen {
        background: #999999;
    }
    #add-container {
        padding: 1 2;
        border: solid black;
        background: #000000;
        margin: 1 2;
        height: auto;
        min-height: 20;
    }
    .field-label {
        color: #ffffff;
        text-style: bold;
        margin-top: 1;
    }
    Input, Select, TextArea {
        background: #ffffff;
        color: #000000;
        border: solid black;
    }
    #kind-select {
        margin-bottom: 1;
    }
    .hidden {
        display: none;
    }
    #action-row {
        height: 3;
        margin-top: 2;
        content-align: right middle;
    }
    #btn-save {
        background: #ffffff;
        color: #000000;
        border: solid black;
        text-style: bold;
    }
    #btn-cancel {
        background: #000000;
        color: #ffffff;
        border: solid #ffffff;
        text-style: bold;
    }
    """

    def compose(self) -> ComposeResult:
        yield Header()
        with Container(id="add-container"):
            yield Label("ADD NEW ENTRY", id="screen-title")

            yield Label("Kind", classes="field-label")
            # Seed/managed-account derivations are handled by SeedPlusScreen.
            supported_kinds = (
                EntryType.PASSWORD,
                EntryType.TOTP,
                EntryType.DOCUMENT,
                EntryType.KEY_VALUE,
                EntryType.SSH,
                EntryType.PGP,
                EntryType.NOSTR,
            )
            kinds = [(k.value.title(), k.value) for k in supported_kinds]
            yield Select(kinds, value="password", id="kind-select")
            yield Label(
                "Use `seed-plus` for Seed / Managed Account derivations.",
                id="seedplus-hint",
            )

            yield Label("Label", classes="field-label")
            yield Input(placeholder="Label (e.g. Gmail)", id="entry-label")

            # Common fields
            with Vertical(id="fields-common"):
                yield Label(
                    "Username / Email", classes="field-label", id="lbl-username"
                )
                yield Input(placeholder="Username", id="entry-username")

                yield Label("URL", classes="field-label", id="lbl-url")
                yield Input(placeholder="https://...", id="entry-url")

            # Specialized fields (initially hidden/shown based on kind)
            with Vertical(id="fields-password", classes="field-group"):
                yield Label("Password Length", classes="field-label")
                yield Input(value="16", id="entry-length")

            with Vertical(id="fields-totp", classes="field-group hidden"):
                yield Label("TOTP Secret (Base32)", classes="field-label")
                yield Input(placeholder="JBSWY3DPEHPK3PXP", id="entry-totp-secret")

            with Vertical(id="fields-document", classes="field-group hidden"):
                yield Label("Content", classes="field-label")
                yield TextArea(id="entry-content")

            with Vertical(id="fields-keyvalue", classes="field-group hidden"):
                yield Label("Key", classes="field-label")
                yield Input(placeholder="Key", id="entry-key")
                yield Label("Value", classes="field-label")
                yield Input(placeholder="Value", id="entry-value")

            yield Label("Tags (comma separated)", classes="field-label")
            yield Input(placeholder="work, personal", id="entry-tags")

            with Horizontal(id="action-row"):
                yield Button("Cancel (Esc)", id="btn-cancel", variant="error")
                yield Button("Save (Ctrl+S)", id="btn-save", variant="success")
        yield Footer()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "kind-select":
            self._update_visible_fields(str(event.value))

    def _update_visible_fields(self, kind: str) -> None:
        # Hide all groups first
        for group in self.query(".field-group"):
            group.add_class("hidden")

        # Show specific ones
        if kind == "password":
            self.query_one("#fields-password").remove_class("hidden")
        elif kind == "totp":
            self.query_one("#fields-totp").remove_class("hidden")
        elif kind in {"document", "note"}:
            self.query_one("#fields-document").remove_class("hidden")
        elif kind == "key_value":
            self.query_one("#fields-keyvalue").remove_class("hidden")

        # Toggle common fields visibility if needed
        common = self.query_one("#fields-common")
        if kind in {"ssh", "pgp", "nostr", "seed", "managed_account"}:
            common.add_class("hidden")
        else:
            common.remove_class("hidden")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-save":
            self.action_save()
        else:
            self.app.pop_screen()

    def action_save(self) -> None:
        kind = str(self.query_one("#kind-select", Select).value)
        label = self.query_one("#entry-label", Input).value
        tags_raw = self.query_one("#entry-tags", Input).value
        tags = [t.strip() for t in tags_raw.split(",") if t.strip()]

        if not label:
            self.app.notify("Label is required", severity="error")
            return

        try:
            service = self.app.services["entry"]
            if kind == "password":
                length = int(self.query_one("#entry-length", Input).value or 16)
                username = self.query_one("#entry-username", Input).value
                url = self.query_one("#entry-url", Input).value
                service.add_entry(
                    label=label, username=username, url=url, length=length, tags=tags
                )
            elif kind == "totp":
                secret = self.query_one("#entry-totp-secret", Input).value
                username = self.query_one("#entry-username", Input).value
                service.add_totp(
                    label=label, secret=secret, username=username, tags=tags
                )
            elif kind == "ssh":
                service.add_ssh_key(label=label, tags=tags)
            elif kind == "pgp":
                service.add_pgp_key(label=label, tags=tags)
            elif kind == "nostr":
                service.add_nostr_key(label=label, tags=tags)
            elif kind == "key_value":
                key = self.query_one("#entry-key", Input).value
                val = self.query_one("#entry-value", Input).value
                service.add_key_value(label=label, key=key, value=val, tags=tags)
            elif kind in {"document", "note"}:
                content = self.query_one("#entry-content", TextArea).text
                service.add_document(label=label, content=content, tags=tags)
            else:
                self.app.notify(
                    f"Adding '{kind}' not yet implemented in v3 screen",
                    severity="warning",
                )
                return

            self.app.notify(f"Added {kind}: {label}")
            self.app.action_refresh()
            self.app.pop_screen()
        except Exception as e:
            self.app.notify(f"Failed to add entry: {e}", severity="error")


class SeedPlusScreen(Screen):
    """
    Specialized screen for BIP-85 derivations (Seeds and Managed Accounts).
    """

    BINDINGS = [
        Binding("ctrl+s", "save", "Save", show=True),
        Binding("escape", "app.pop_screen", "Cancel", show=True),
    ]

    CSS = """
    SeedPlusScreen {
        background: #0d1114;
    }
    #seed-container {
        padding: 1 2;
        border: heavy #58f29d;
        margin: 1 2;
        height: auto;
    }
    .field-label {
        color: #58f29d;
        text-style: bold;
        margin-top: 1;
    }
    Input, Select {
        background: #11191f;
        color: #e4fff2;
        border: solid #1a3024;
    }
    #action-row {
        height: 3;
        margin-top: 2;
        content-align: right middle;
    }
    """

    def compose(self) -> ComposeResult:
        yield Header()
        with Container(id="seed-container"):
            yield Label("SEED+ / BIP-85 DERIVATION", id="screen-title")

            yield Label("Derivation Type", classes="field-label")
            yield Select(
                [("New BIP-39 Seed", "seed"), ("Managed Account", "managed_account")],
                value="seed",
                id="seed-kind",
            )

            yield Label("Label", classes="field-label")
            yield Input(placeholder="Label", id="seed-label")

            yield Label("Index", classes="field-label")
            yield Input(value="0", id="seed-index")

            yield Label("Tags", classes="field-label")
            yield Input(placeholder="tags", id="seed-tags")

            with Horizontal(id="action-row"):
                yield Button("Cancel", id="btn-cancel", variant="error")
                yield Button("Derive & Save", id="btn-save", variant="success")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-save":
            self.action_save()
        else:
            self.app.pop_screen()

    def action_save(self) -> None:
        kind = str(self.query_one("#seed-kind", Select).value)
        label = self.query_one("#seed-label", Input).value
        try:
            index = int(self.query_one("#seed-index", Input).value or 0)
        except ValueError:
            self.app.notify("Index must be an integer", severity="error")
            return

        tags = [
            t.strip()
            for t in self.query_one("#seed-tags", Input).value.split(",")
            if t.strip()
        ]

        if not label:
            self.app.notify("Label is required", severity="error")
            return

        try:
            service = self.app.services["entry"]
            if kind == "seed":
                service.add_seed(label=label, index=index, tags=tags)
            else:
                service.add_managed_account(label=label, index=index, tags=tags)

            self.app.notify(f"Derived {kind}: {label} (Index {index})")
            self.app.action_refresh()
            self.app.pop_screen()
        except Exception as e:
            self.app.notify(f"Derivation failed: {e}", severity="error")
