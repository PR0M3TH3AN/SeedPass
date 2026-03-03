from __future__ import annotations
from typing import Any
from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Static, Footer
from textual.containers import Vertical, Horizontal
from textual.reactive import reactive

class MaximizedInspectorScreen(Screen):
    """
    Full-screen detailed view for a single entry.
    Optimized for long documents, SSH keys, or PGP blocks.
    """
    reveal_data = reactive[dict[str, Any]]({})

    def watch_reveal_data(self, old, new):
        self._refresh_detail()
    
    BINDINGS = [
        ("escape", "app.pop_screen", "Back to Vault"),
        ("v", "reveal", "Reveal Secret"),
        ("g", "qr", "Show QR"),
    ]

    DEFAULT_CSS = """
    MaximizedInspectorScreen {
        background: #080a0c;
    }
    #max-inspector-title {
        background: #0b0f13;
        color: #58f29d;
        text-style: bold;
        text-align: center;
        height: 3;
        border: double #2abf75;
        padding: 0 1;
        margin: 1 2;
    }
    #max-inspector-container {
        height: 1fr;
        margin: 0 2;
        border: solid #1a3024;
        padding: 1;
        overflow: auto;
    }
    #max-inspector-footer {
        height: 3;
        background: #11191f;
        color: #daf2e5;
        text-align: center;
        border: double #2abf75;
        padding: 0 1;
        margin: 1 2;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static("SeedPass ◈ Detailed Inspection", id="max-inspector-title")
        with Vertical(id="max-inspector-container"):
            yield Static("Loading details...", id="max-inspector-content")
        yield Static("ESC: Back | v: Reveal | g: QR", id="max-inspector-footer")

    def on_mount(self) -> None:
        self._refresh_detail()

    def _refresh_detail(self) -> None:
        app = self.app
        eid = app.selected_entry_id
        r = self.reveal_data

        if eid is None:
            self.query_one("#max-inspector-content", Static).update("No entry selected.")
            return

        if r.get("prompt"):
            self.query_one("#max-inspector-content", Static).update(f"[b]SECURITY ALERT[/b]\n\n{r['prompt']}")
            return

        if r.get("content") and "##" in r["content"]:
            self.query_one("#max-inspector-content", Static).update(f"[b]SECURE QR DISPLAY[/b]\n\n{r['content']}")
            return

        if "entry" not in app.services:
            return

        entry = app.services["entry"].retrieve_entry(eid)
        if not entry:
            return

        # Simple render for the full screen view
        label = entry.get('label', 'Unknown')
        kind = entry.get('kind', 'Unknown')
        
        # Build a large detail view
        header = f"[b]ENTRY #{eid} - {label.upper()} ({kind})[/b]\n"
        divider = "=" * 60 + "\n"
        
        # Meta info
        meta_lines = [
            f"Username : {entry.get('username', '(none)')}",
            f"URL      : {entry.get('url', '(none)')}",
            f"Created  : {entry.get('created_at', '(unknown)')}",
            f"Modified : {entry.get('modified_at', '(unknown)')}",
        ]
        
        # Handle revealed content
        content = entry.get('content', '')
        if r.get("content"):
            content = f"[b][cyan]{r['content']}[/b]"
        
        content_block = f"\n[b]CONTENT / SECURE DATA:[/b]\n{divider}{content}\n" if content else ""
        
        final_text = header + divider + "\n".join(meta_lines) + content_block
        self.query_one("#max-inspector-content", Static).update(final_text)

    def action_reveal(self) -> None:
        self.app.action_reveal_selected()

    def action_qr(self) -> None:
        self.app.action_show_qr()
