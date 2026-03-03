from __future__ import annotations
from typing import Any
from textual.app import ComposeResult
from textual.widgets import Static, DataTable
from textual.reactive import reactive

class GridMetrics(Static):
    """
    Displays pagination, row counts, and search mode state.
    Matches the 'Entry Grid | Pg X/X ...' line in the mockups.
    """
    DEFAULT_CSS = """
    GridMetrics {
        height: 1;
        background: #0b0f13;
        color: #daf2e5;
        padding: 0 1;
    }
    """
    
    def render(self) -> str:
        # These would eventually come from App reactives
        pg = "1/1"
        rows = "0/0"
        density = "compact"
        # Search mode highlighting
        search = "[b](KEYWORD)[/b] hybrid semantic"
        
        return f"Entry Grid  |  Pg {pg}  Rows {rows}  Density {density}  Search {search}"

class EntryDataTable(DataTable):
    """
    High-fidelity data table for entry browsing.
    """
    def on_mount(self) -> None:
        self.cursor_type = "row"
        self.add_columns(
            "Sel", "Id", "Entry#", "Label", "Kind", "Meta", "Arch"
        )
        self._refresh_data()

    def on_focus(self) -> None:
        """Refresh table when focused so newly added entries appear immediately."""
        try:
            self._refresh_data()
        except Exception:
            pass

    def _refresh_data(self, query: str = "") -> None:
        self.clear()
        app = self.app
        if "entry" not in app.services:
            return

        # Fetch filtered data from service
        entries = app.services["entry"].search_entries(query)
        for i, (eid, label, user, url, arch, kind) in enumerate(entries):
            marker = "▶" if eid == app.selected_entry_id else " "
            arch_status = "🔒" if arch else " "
            # 'Meta' column logic from mockup
            meta = user or url or ""
            
            self.add_row(
                marker,
                str(i+1),
                f"#{eid}",
                label,
                kind.value,
                meta,
                arch_status,
                key=str(eid)
            )

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        """Update selection when moving cursor."""
        rk = str(event.row_key.value) if event.row_key else None
        if rk:
            try:
                self.app.selected_entry_id = int(rk)
            except ValueError:
                pass

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle explicit entry selection (Enter)."""
        rk = str(event.row_key.value) if event.row_key else None
        if rk:
            try:
                eid = int(rk)
                self.app.selected_entry_id = eid
                self.app.notify(f"Selected Entry #{eid}")
            except ValueError:
                pass

class GridContainer(Static):
    """
    The central workspace container.
    """
    def compose(self) -> ComposeResult:
        yield GridMetrics()
        # Header divider
        yield Static("-" * 120, id="grid-divider")
        yield EntryDataTable(id="entry-data-table")

    DEFAULT_CSS = """
    GridContainer {
        height: 1fr;
        background: #0d1114;
    }
    #grid-divider {
        color: #1a3024;
        height: 1;
        padding: 0 1;
    }
    #entry-data-table {
        background: transparent;
        color: #97b8a6;
        border: none;
        height: 1fr;
    }
    #entry-data-table > .datatable--header {
        background: #0b0f13;
        color: #58f29d;
        text-style: bold;
    }
    #entry-data-table > .datatable--cursor {
        background: #122019;
        color: #58f29d;
    }
    """
