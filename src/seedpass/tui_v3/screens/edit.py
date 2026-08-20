from __future__ import annotations
from typing import Any
from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Header, Footer, Input, TextArea, Label, Button
from textual.containers import Vertical, Horizontal, Container
from textual.binding import Binding


class EditEntryScreen(Screen):
    """
    Dedicated full-screen editor for all entries.
    Auto-detects the entry kind and shows relative fields.
    """

    BINDINGS = [
        Binding("ctrl+s", "save", "Save", show=True),
        Binding("escape", "app.pop_screen", "Cancel", show=True),
    ]

    CSS = """
    EditEntryScreen {
        background: #999999;
    }
    #editor-container {
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
    Input, TextArea {
        background: #ffffff;
        color: #000000;
        border: solid #999999;
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
        text-style: bold;
    }
    #doc-content, #entry-notes {
        height: 1fr;
        min-height: 5;
    }
    """

    def __init__(self, entry_id: int, **kwargs) -> None:
        super().__init__(**kwargs)
        self.entry_id = entry_id
        self.entry_data: dict[str, Any] = {}
        self.kind = ""

    def on_mount(self) -> None:
        if "entry" in self.app.services:
            self.entry_data = self.app.services["entry"].retrieve_entry(self.entry_id)
            self.kind = str(
                self.entry_data.get("kind") or self.entry_data.get("type") or ""
            ).lower()

            # Common fields
            self.query_one("#entry-title", Input).value = self.entry_data.get(
                "label", ""
            )
            self.query_one("#entry-tags", Input).value = ", ".join(
                self.entry_data.get("tags", []) or []
            )
            self.query_one("#entry-notes", TextArea).text = self.entry_data.get(
                "notes", ""
            )

            # Kind specific fields
            if self.kind in {"password", "totp"}:
                self.query_one("#fields-user-url").remove_class("hidden")
                self.query_one("#entry-username", Input).value = self.entry_data.get(
                    "username", ""
                )
                self.query_one("#entry-url", Input).value = self.entry_data.get(
                    "url", ""
                )
            elif self.kind == "key_value":
                self.query_one("#fields-keyvalue").remove_class("hidden")
                self.query_one("#entry-key", Input).value = self.entry_data.get(
                    "key", ""
                )
                self.query_one("#entry-value", Input).value = self.entry_data.get(
                    "value", ""
                )
            elif self.kind in {"document", "note"}:
                self.query_one("#fields-document").remove_class("hidden")
                self.query_one("#doc-type", Input).value = self.entry_data.get(
                    "file_type", "txt"
                )
                self.query_one("#doc-content", TextArea).text = self.entry_data.get(
                    "content", ""
                )

    def compose(self) -> ComposeResult:
        yield Header()
        with Container(id="editor-container"):
            yield Label(f"EDIT ENTRY #{self.entry_id}", id="screen-title")

            with Horizontal(id="edit-row"):
                with Vertical(id="col-left"):
                    yield Label("Title / Label", classes="field-label")
                    yield Input(placeholder="Title", id="entry-title")
                with Vertical(id="col-right"):
                    yield Label("Tags (comma separated)", classes="field-label")
                    yield Input(placeholder="work, personal...", id="entry-tags")

            # Optional fields
            with Vertical(id="fields-user-url", classes="hidden"):
                yield Label("Username / Email", classes="field-label")
                yield Input(placeholder="Username", id="entry-username")
                yield Label("URL", classes="field-label")
                yield Input(placeholder="https://...", id="entry-url")

            with Vertical(id="fields-keyvalue", classes="hidden"):
                yield Label("Key", classes="field-label")
                yield Input(placeholder="Key", id="entry-key")
                yield Label("Value", classes="field-label")
                yield Input(placeholder="Value", id="entry-value")

            with Vertical(id="fields-document", classes="hidden"):
                yield Label("File Type", classes="field-label")
                yield Input(placeholder="txt", id="doc-type")
                yield Label("Content", classes="field-label")
                yield TextArea(id="doc-content")

            yield Label("Notes", classes="field-label")
            yield TextArea(id="entry-notes")

            with Horizontal(id="action-row"):
                yield Button("Cancel (Esc)", id="btn-cancel", variant="error")
                yield Button("Save (Ctrl+S)", id="btn-save", variant="success")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-save":
            self.action_save()
        else:
            self.app.pop_screen()

    def action_save(self) -> None:
        title = self.query_one("#entry-title", Input).value
        tags_raw = self.query_one("#entry-tags", Input).value
        notes = self.query_one("#entry-notes", TextArea).text
        tags = [t.strip() for t in tags_raw.split(",") if t.strip()]

        update_args = {
            "label": title,
            "tags": tags,
            "notes": notes,
        }

        # Add kind-specific fields
        if self.kind in {"password", "totp"}:
            update_args["username"] = self.query_one("#entry-username", Input).value
            update_args["url"] = self.query_one("#entry-url", Input).value
        elif self.kind == "key_value":
            update_args["key"] = self.query_one("#entry-key", Input).value
            update_args["value"] = self.query_one("#entry-value", Input).value
        elif self.kind in {"document", "note"}:
            update_args["file_type"] = self.query_one("#doc-type", Input).value
            update_args["content"] = self.query_one("#doc-content", TextArea).text

        try:
            self.app.services["entry"].modify_entry(self.entry_id, **update_args)
            self.app.notify(f"Entry #{self.entry_id} saved successfully")
            self.app.action_refresh()
            self.app.pop_screen()
        except Exception as e:
            self.app.notify(f"Save failed: {e}", severity="error")
