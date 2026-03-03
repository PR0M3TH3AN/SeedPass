from __future__ import annotations
from typing import Any
from textual.app import ComposeResult
from textual.widgets import Static, Label
from textual.containers import Vertical, Horizontal
from textual.reactive import reactive

class BaseBoard(Static):
    """Base class for all specialized entry boards."""
    entry_data = reactive[dict[str, Any]]({})

    def _render_card(self, title: str, rows: list[str]) -> str:
        """Utility to render ASCII cards matching mockup style."""
        width = 40
        top = f"┌─ {title} " + "─" * (width - len(title) - 4) + "┐"
        bottom = "└" + "─" * (width - 2) + "┘"
        lines = [top]
        for row in rows:
            lines.append(f"│ {row:<{width-4}} │")
        lines.append(bottom)
        return "
".join(lines)

class IdleBoard(Static):
    """Shown when no entry is selected."""
    def render(self) -> str:
        return "


[b]Inspector Idle[/b]

Select an entry from the grid
to view details."

class PasswordBoard(BaseBoard):
    """Matches 'Password Board.png' mockup."""
    def render(self) -> str:
        d = self.entry_data
        cred_rows = [
            f"Label    : {d.get('label', '')}",
            f"Username : {d.get('username', '')}",
            f"URL      : {d.get('url', '')}",
            "Password : [HIDDEN]",
        ]
        action_rows = [
            "▣ Reveal (v)  ▣ QR (g)",
            "▣ Edit (e)    ▣ Archive (a)",
        ]
        
        return "
".join([
            self._render_card("Credentials", cred_rows),
            "",
            self._render_card("Quick Actions", action_rows)
        ])

class NoteBoard(BaseBoard):
    """Matches 'Note Board.png' mockup."""
    def render(self) -> str:
        d = self.entry_data
        content = d.get('content', '')
        # Truncate for preview
        preview = (content[:200] + '...') if len(content) > 200 else content
        
        content_rows = preview.splitlines()[:10]
        action_rows = [
            "▣ Edit Doc (e)  ▣ Export",
            "▣ Archive (a)",
        ]
        
        return "
".join([
            self._render_card("Content", content_rows),
            "",
            self._render_card("Quick Actions", action_rows)
        ])

class BoardContainer(Vertical):
    """
    Reactive container that swaps specialized boards based on entry kind.
    """
    DEFAULT_CSS = """
    BoardContainer {
        height: 1fr;
        padding: 1;
        content-align: center top;
    }
    """

    def on_mount(self) -> None:
        self._show_board("idle")

    def update_entry(self, entry_id: int | None) -> None:
        if entry_id is None:
            self._show_board("idle")
            return

        app = self.app
        if "entry" not in app.services:
            return

        entry = app.services["entry"].retrieve_entry(entry_id)
        if not entry:
            self._show_board("idle")
            return

        kind = str(entry.get("kind") or entry.get("type") or "").lower()
        
        # Select appropriate board
        if kind in {"password", "stored_password"}:
            board = self._show_board("password")
            board.entry_data = entry
        elif kind in {"document", "note"}:
            board = self._show_board("note")
            board.entry_data = entry
        else:
            # Fallback for now
            board = self._show_board("password")
            board.entry_data = entry

    def _show_board(self, board_type: str) -> Any:
        self.remove_children()
        if board_type == "idle":
            new_board = IdleBoard()
        elif board_type == "password":
            new_board = PasswordBoard()
        elif board_type == "note":
            new_board = NoteBoard()
        else:
            new_board = IdleBoard()
            
        self.mount(new_board)
        return new_board
