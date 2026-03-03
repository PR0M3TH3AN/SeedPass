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
        width = 50
        top = f"┌─ {title} " + "─" * (width - len(title) - 4) + "┐"
        bottom = "└" + "─" * (width - 2) + "┘"
        lines = [top]
        for row in rows:
            lines.append(f"│ {row:<{width-4}} │")
        lines.append(bottom)
        return "\n".join(lines)

class IdleBoard(Static):
    """Shown when no entry is selected."""
    def render(self) -> str:
        return """


[b]Inspector Idle[/b]

Select an entry from the grid
to view details."""

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
            "▣ Edit (e)    ▣ Archive (a)  ▣ Max (z)",
        ]
        
        return "\n".join([
            self._render_card("Credentials", cred_rows),
            "",
            self._render_card("Quick Actions", action_rows)
        ])

class TotpBoard(BaseBoard):
    """Matches '2FA Board.png' mockup."""
    def render(self) -> str:
        d = self.entry_data
        app = self.app
        code = "------"
        if app.services.get("entry") and not app.session_locked:
            try:
                code = app.services["entry"].get_totp_code(d.get("id"))
            except:
                pass

        import time
        remaining = 30 - (int(time.time()) % 30)
        bar_width = 20
        filled = int((remaining / 30) * bar_width)
        bar = "█" * filled + "░" * (bar_width - filled)

        cred_rows = [
            f"Label    : {d.get('label', '')}",
            f"Code     : [b][cyan]{code}[/b]  ({remaining}s)",
            f"Timer    : {bar}",
            f"Period   : {d.get('period', 30)}s",
            f"Digits   : {d.get('digits', 6)}",
        ]
        action_rows = [
            "▣ Copy Code (c)  ▣ Reveal Secret (v)",
            "▣ Show QR (g)    ▣ Archive (a)  ▣ Max (z)",
        ]
        
        return "\n".join([
            self._render_card("2FA Authenticator", cred_rows),
            "",
            self._render_card("Quick Actions", action_rows)
        ])

class SeedBoard(BaseBoard):
    """Matches 'BIP-39 Seed Board.png' mockup."""
    def render(self) -> str:
        d = self.entry_data
        cred_rows = [
            f"Label      : {d.get('label', '')}",
            f"Fingerprint: {d.get('fingerprint', 'Pending...')}",
            f"Index      : {d.get('index', 0)}",
            f"Word Count : {d.get('word_count', 24)}",
            "Seed Phrase: [HIDDEN] (vv to reveal)",
        ]
        action_rows = [
            "▣ Reveal Words (vv)  ▣ Show SeedQR (gg)",
            "▣ Load Session (ml)  ▣ Archive (a)  ▣ Max (z)",
        ]
        
        return "\n".join([
            self._render_card("BIP-85 Derived Seed", cred_rows),
            "",
            self._render_card("Quick Actions", action_rows)
        ])

class SshBoard(BaseBoard):
    """Matches 'SSH Board.png' mockup."""
    def render(self) -> str:
        d = self.entry_data
        cred_rows = [
            f"Label    : {d.get('label', '')}",
            f"Key Type : {d.get('key_type', 'RSA/Ed25519')}",
            f"Index    : {d.get('index', 0)}",
            "Pub Key  : [PREVIEW AVAILABLE]",
            "Priv Key : [HIDDEN] (vv to reveal)",
        ]
        action_rows = [
            "▣ Copy Pub (c)  ▣ Reveal Priv (vv)",
            "▣ Export (x)    ▣ Archive (a)  ▣ Max (z)",
        ]
        
        return "\n".join([
            self._render_card("SSH Key Pair", cred_rows),
            "",
            self._render_card("Quick Actions", action_rows)
        ])

class PgpBoard(BaseBoard):
    """Matches 'PGP Board.png' mockup."""
    def render(self) -> str:
        d = self.entry_data
        cred_rows = [
            f"Label    : {d.get('label', '')}",
            f"Identity : {d.get('user_id', '')}",
            f"Fingerpr : {d.get('fingerprint', '')}",
            "Priv Key : [HIDDEN] (vv to reveal)",
        ]
        action_rows = [
            "▣ Copy Pub (c)  ▣ Reveal Priv (vv)",
            "▣ Export (x)    ▣ Archive (a)  ▣ Max (z)",
        ]
        
        return "\n".join([
            self._render_card("PGP Key Pair", cred_rows),
            "",
            self._render_card("Quick Actions", action_rows)
        ])

class NostrBoard(BaseBoard):
    """Matches 'Nostr Board.png' mockup."""
    def render(self) -> str:
        d = self.entry_data
        cred_rows = [
            f"Label    : {d.get('label', '')}",
            f"npub     : {d.get('npub', '')[:20]}...",
            "nsec     : [HIDDEN] (v to reveal)",
        ]
        action_rows = [
            "▣ Reveal (v)    ▣ QR (g)",
            "▣ Sync (s)      ▣ Archive (a)  ▣ Max (z)",
        ]
        
        return "\n".join([
            self._render_card("Nostr Agent Identity", cred_rows),
            "",
            self._render_card("Quick Actions", action_rows)
        ])

class KeyValueBoard(BaseBoard):
    """Generic meta-data board."""
    def render(self) -> str:
        d = self.entry_data
        rows = [
            f"Label    : {d.get('label', '')}",
            f"Key      : {d.get('key', '')}",
            f"Value    : {d.get('value', '')}",
        ]
        action_rows = [
            "▣ Edit (e)      ▣ Archive (a)  ▣ Max (z)",
        ]
        
        return "\n".join([
            self._render_card("Key-Value Meta", rows),
            "",
            self._render_card("Quick Actions", action_rows)
        ])

class NoteBoard(BaseBoard):
    """Matches 'Note Board.png' mockup."""
    def render(self) -> str:
        d = self.entry_data
        content = str(d.get('content', ''))
        preview = (content[:200] + '...') if len(content) > 200 else content
        
        content_rows = preview.splitlines()[:10]
        action_rows = [
            "▣ Edit Doc (e)  ▣ Export",
            "▣ Archive (a)   ▣ Max (z)",
        ]
        
        return "\n".join([
            self._render_card("Content Preview", content_rows),
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
        
        if kind in {"password", "stored_password"}:
            board = self._show_board("password")
        elif kind in {"document", "note"}:
            board = self._show_board("note")
        elif kind == "totp":
            board = self._show_board("totp")
        elif kind in {"seed", "managed_account"}:
            board = self._show_board("seed")
        elif kind == "ssh":
            board = self._show_board("ssh")
        elif kind == "pgp":
            board = self._show_board("pgp")
        elif kind == "nostr":
            board = self._show_board("nostr")
        elif kind == "key_value":
            board = self._show_board("key_value")
        else:
            board = self._show_board("password")
            
        board.entry_data = entry

    def _show_board(self, board_type: str) -> Any:
        self.remove_children()
        mapping = {
            "idle": IdleBoard,
            "password": PasswordBoard,
            "note": NoteBoard,
            "totp": TotpBoard,
            "seed": SeedBoard,
            "ssh": SshBoard,
            "pgp": PgpBoard,
            "nostr": NostrBoard,
            "key_value": KeyValueBoard,
        }
        board_cls = mapping.get(board_type, IdleBoard)
        new_board = board_cls()
        self.mount(new_board)
        return new_board
