from __future__ import annotations
from textual.app import ComposeResult
from textual.widgets import Static
from textual.reactive import reactive


class RibbonHeader(Static):
    """
    A high-density status ribbon that displays active profile,
    session state, and vault metrics.

    Matches the 'UI Board' mockup top ribbon layout.
    """

    DEFAULT_CSS = """
    RibbonHeader {
        height: 1;
        background: #999999;
        color: #000000;
        padding: 0 1;
        margin: 0;
        text-style: bold;
    }
    """

    def render(self) -> str:
        app = self.app

        # Gather metrics from actual services
        managed = 0
        try:
            managed = len(
                getattr(app.services.get("vault")._manager, "profile_stack", [])
            )
        except:
            pass

        entries = 0
        try:
            table = app.screen.query_one("#entry-data-table")
            if table:
                entries = len(table.rows)
        except:
            pass

        sync = "YYY-MM-DDThh:mm:ssTZD"

        # Build the exact string parts from the mockup
        left = f"Managed Users: {managed}       Entries: {entries}       ◀ ▶ Kind = {app.filter_kind.capitalize()}"
        right = f"Last Sync: {sync}"

        # Calculate spacing to push sync to the right edge
        available_width = self.size.width - len(left) - len(right) - 2
        spacer = " " * max(1, available_width)

        return f"{left}{spacer}{right}"

    def on_mount(self) -> None:
        # Refresh the header whenever important app state changes
        self.watch(self.app, "active_fingerprint", self.refresh)
        self.watch(self.app, "session_locked", self.refresh)
        self.watch(self.app, "filter_kind", self.refresh)


class AtlasStrip(Static):
    """Compact wayfinder strip for the active scope."""

    DEFAULT_CSS = """
    AtlasStrip {
        height: 2;
        background: #d9d9d9;
        color: #000000;
        padding: 0 1;
        border-top: solid black;
        border-bottom: solid black;
        text-style: bold;
    }
    """

    def render(self) -> str:
        app = self.app
        atlas = app.services.get("atlas")
        if atlas is None:
            return "Wayfinder  |  Atlas unavailable"
        try:
            payload = atlas.wayfinder()
        except Exception:
            return "Wayfinder  |  Atlas unavailable"

        scope = str(payload.get("scope_path", "unknown"))
        counts = ((payload.get("counts_by_kind") or {}).get("data") or {}).get(
            "counts", {}
        )
        recent_items = ((payload.get("recent_activity") or {}).get("data") or {}).get(
            "items", []
        )
        top_counts = ", ".join(
            f"{kind}:{count}" for kind, count in sorted(counts.items())[:3]
        )
        if not top_counts:
            top_counts = "no entries"
        recent = "no recent activity"
        if recent_items:
            item = recent_items[0]
            recent = (
                f"{item.get('event_type', 'event')} #{item.get('subject_id', '?')} "
                f"({item.get('subject_kind', 'entry')})"
            )
        return f"Wayfinder  |  {scope}  |  Counts {top_counts}  |  Recent {recent}"

    def on_mount(self) -> None:
        self.watch(self.app, "active_fingerprint", self.refresh)
        self.watch(self.app, "selected_entry_id", self.refresh)
