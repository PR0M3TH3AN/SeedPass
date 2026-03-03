from __future__ import annotations
from typing import Any
from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Header, Footer, Input, TextArea, Label, Button
from textual.containers import Vertical, Horizontal, Container
from textual.binding import Binding

class DocumentEditScreen(Screen):
    """
    Dedicated full-screen editor for document/note entries.
    Matches the 'Document Editor' mockup style.
    """
    
    BINDINGS = [
        Binding("ctrl+s", "save", "Save", show=True),
        Binding("escape", "app.pop_screen", "Cancel", show=True),
    ]
    
    CSS = """
    DocumentEditScreen {
        background: #0d1114;
    }
    #editor-container {
        padding: 1 2;
        border: heavy #2abf75;
        margin: 1 2;
        height: 1fr;
    }
    .field-label {
        color: #58f29d;
        text-style: bold;
        margin-top: 1;
    }
    #doc-title, #doc-tags, #doc-type {
        background: #11191f;
        color: #e4fff2;
        border: solid #1a3024;
    }
    #doc-content {
        height: 1fr;
        margin-top: 1;
        background: #11191f;
        color: #e4fff2;
        border: solid #1a3024;
    }
    #action-row {
        height: 3;
        margin-top: 1;
        content-align: right middle;
    }
    #btn-save {
        background: #2abf75;
        color: #0b0f13;
        text-style: bold;
    }
    """

    def __init__(self, entry_id: int, **kwargs) -> None:
        super().__init__(**kwargs)
        self.entry_id = entry_id
        self.entry_data: dict[str, Any] = {}

    def on_mount(self) -> None:
        if "entry" in self.app.services:
            self.entry_data = self.app.services["entry"].retrieve_entry(self.entry_id)
            self.query_one("#doc-title", Input).value = self.entry_data.get("label", "")
            self.query_one("#doc-type", Input).value = self.entry_data.get("file_type", "txt")
            self.query_one("#doc-tags", Input).value = ", ".join(self.entry_data.get("tags", []))
            self.query_one("#doc-content", TextArea).text = self.entry_data.get("content", "")

    def compose(self) -> ComposeResult:
        yield Header()
        with Container(id="editor-container"):
            yield Label("DOCUMENT EDITOR", id="screen-title")
            
            with Horizontal(height=4):
                with Vertical(id="col-left"):
                    yield Label("Title", classes="field-label")
                    yield Input(placeholder="Title", id="doc-title")
                with Vertical(id="col-right", margin_left=2):
                    yield Label("Type", classes="field-label")
                    yield Input(placeholder="txt", id="doc-type")
            
            yield Label("Tags (comma separated)", classes="field-label")
            yield Input(placeholder="work, personal...", id="doc-tags")
            
            yield Label("Content", classes="field-label")
            yield TextArea(id="doc-content")
            
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
        title = self.query_one("#doc-title", Input).value
        file_type = self.query_one("#doc-type", Input).value
        tags_raw = self.query_one("#doc-tags", Input).value
        content = self.query_one("#doc-content", TextArea).text
        
        tags = [t.strip() for t in tags_raw.split(",") if t.strip()]
        
        try:
            self.app.services["entry"].modify_entry(
                self.entry_id,
                label=title,
                file_type=file_type,
                tags=tags,
                content=content
            )
            self.app.notify(f"Document #{self.entry_id} saved successfully")
            self.app.action_refresh()
            self.app.pop_screen()
        except Exception as e:
            self.app.notify(f"Save failed: {e}", severity="error")
