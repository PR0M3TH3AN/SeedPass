from __future__ import annotations
from typing import Any
from textual.app import ComposeResult
from textual.widgets import Input, Static
from textual.containers import Vertical
from textual.message import Message


class CommandPalette(Vertical):
    """
    The TUI v3 Command Palette.
    Docks at the top and provides a unified entry point for all actions.
    """

    DEFAULT_CSS = """
    CommandPalette {
        dock: top;
        height: 4;
        background: #0b0f13;
        color: #daf2e5;
        border-bottom: solid #2abf75;
        display: none;
        padding: 0 1;
    }
    CommandPalette.visible {
        display: block;
    }
    #palette-label {
        height: 1;
        color: #58f29d;
        text-style: bold;
        margin-left: 1;
    }
    #palette-input {
        background: #0d1114;
        border: solid #1a3024;
        color: #e4fff2;
    }
    #palette-input:focus {
        border: heavy #58f29d;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static("COMMAND PALETTE (type 'help' for list)", id="palette-label")
        yield Input(placeholder="enter command...", id="palette-input")

    def on_mount(self) -> None:
        self.input = self.query_one("#palette-input", Input)

    def toggle(self) -> None:
        if self.has_class("visible"):
            self.remove_class("visible")
            try:
                self.app.screen.query_one("#entry-data-table").focus()
            except Exception:
                self.app.set_focus(None)
        else:
            self.add_class("visible")
            self.input.focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Forward the command to the main app."""
        cmd = event.value.strip()
        if cmd:
            self.app.post_message(self.CommandExecuted(cmd))
        self.input.value = ""
        self.toggle()  # Close after execution

    class CommandExecuted(Message):
        """Sent when a command is submitted."""

        def __init__(self, command: str) -> None:
            self.command = command
            super().__init__()
