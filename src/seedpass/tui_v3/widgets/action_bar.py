from __future__ import annotations
from typing import Any
from textual.app import ComposeResult
from textual.widgets import Static
from textual.reactive import reactive


class ActionBar(Static):
    """
    Bottom action bar showing global shortcuts and context actions.
    Matches the 'Settings (S)  Add (A) ...' layout.
    """

    DEFAULT_CSS = """
    ActionBar {
        height: auto;
        min-height: 4;
        background: #999999;
        color: #000000;
        border: solid black;
        padding: 0 1;
        margin: 0;
    }
    """

    def render(self) -> str:
        app = self.app
        selected_id = app.selected_entry_id

        # Global Row - mockup format
        is_managed = False
        try:
            is_managed = (
                len(getattr(app.services.get("vault")._manager, "profile_stack", []))
                > 0
            )
        except Exception:
            pass

        exit_hint = (
            "    [@click='app.managed_exit'][b]M[/b]anaged Exit[/]"
            if is_managed
            else ""
        )
        global_row = (
            f"[@click='app.toggle_settings'][b]S[/b]ettings[/]    [@click='app.add_entry'][b]A[/b]dd New Entry[/]    "
            f"[@click='app.seed_plus'][b]C[/b]reate New Seed[/]    "
            f"[@click='app.open_atlas_wayfinder'][b]W[/b]ayfinder[/]    "
            f"[@click='app.open_profile_management'][b]R[/b]emove Seed[/]    "
            f"[@click='app.open_palette'][b]E[/b]xport Data[/]    [@click='app.open_palette'][b]I[/b]mport Data[/]    [@click='app.open_backup_parent_seed'][b]B[/b]ackup Data[/]{exit_hint}"
        )

        # Context Row (added from previous phase parity)
        if selected_id is None:
            context = "Select an entry to view actions."
        else:
            try:
                entry = app.services["entry"].retrieve_entry(selected_id)
                kind = str(entry.get("kind") or entry.get("type") or "").lower()
                actions = self._context_actions(kind, entry)
                context = f"   Context ({kind}): " + " ▣ ".join(actions)
            except Exception:
                context = f"   Error fetching context details for Entry #{selected_id}"

        return f"{global_row}\n{context}"

    def _context_actions(self, kind: str, entry: dict[str, Any]) -> list[str]:
        is_archived = bool(entry.get("archived", False))
        archive_label = "Restore" if is_archived else "Archive"
        archive_action = f"[@click='app.toggle_archive'][b]a[/b] {archive_label}[/]"

        action_map: dict[str, str] = {
            "reveal": "[@click='app.reveal_selected'][b]v[/b] Reveal[/]",
            "qr": "[@click='app.show_qr'][b]g[/b] QR[/]",
            "edit": "[@click='app.edit_selected'][b]e[/b] Edit[/]",
            "archive": archive_action,
            "delete": "[@click='app.delete_selected'][b]d[/b] Delete[/]",
            "copy": "[@click='app.copy_selected'][b]c[/b] Copy[/]",
            "maximize": "[@click='app.maximize_inspector'][b]z[/b] Maximize[/]",
            "load": "[@click='app.managed_load'][b]m[/b] Load[/]",
            "export": "[@click='app.export_selected'][b]x[/b] Export[/]",
        }

        kind_actions: dict[str, list[str]] = {
            "password": ["reveal", "edit", "archive", "delete", "copy", "maximize"],
            "stored_password": [
                "reveal",
                "edit",
                "archive",
                "delete",
                "copy",
                "maximize",
            ],
            "totp": [
                "reveal",
                "qr",
                "edit",
                "archive",
                "delete",
                "copy",
                "export",
                "maximize",
            ],
            "seed": [
                "reveal",
                "qr",
                "edit",
                "archive",
                "delete",
                "copy",
                "load",
                "maximize",
            ],
            "managed_account": [
                "reveal",
                "edit",
                "archive",
                "delete",
                "copy",
                "load",
                "maximize",
            ],
            "ssh": [
                "reveal",
                "edit",
                "archive",
                "delete",
                "copy",
                "export",
                "maximize",
            ],
            "pgp": [
                "reveal",
                "edit",
                "archive",
                "delete",
                "copy",
                "export",
                "maximize",
            ],
            "nostr": [
                "reveal",
                "qr",
                "edit",
                "archive",
                "delete",
                "copy",
                "export",
                "maximize",
            ],
            "document": ["edit", "archive", "delete", "copy", "export", "maximize"],
            "note": ["edit", "archive", "delete", "copy", "export", "maximize"],
            "key_value": ["reveal", "edit", "archive", "delete", "copy", "maximize"],
        }

        keys = kind_actions.get(kind, ["edit", "archive", "delete", "maximize"])
        return [action_map[key] for key in keys]

    def on_mount(self) -> None:
        self.watch(self.app, "selected_entry_id", self.refresh)
        self.watch(self.app, "active_fingerprint", self.refresh)
