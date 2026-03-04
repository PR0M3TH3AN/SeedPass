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
        app = self.app
        # These would eventually come from App reactives
        pg = "1/1"
        rows = "0/0"
        try:
            table = app.screen.query_one("#entry-data-table")
            if table:
                rows = (
                    f"{len(table.rows)}/{len(table.rows)}"  # TODO: handle actual total
                )
        except Exception:
            pass

        density = "compact"
        # Search mode highlighting
        m = app.search_mode
        keyword = f"[b](KEYWORD)[/b]" if m == "keyword" else "keyword"
        hybrid = f"[b](HYBRID)[/b]" if m == "hybrid" else "hybrid"
        semantic = f"[b](SEMANTIC)[/b]" if m == "semantic" else "semantic"

        search = f"{keyword} {hybrid} {semantic}"
        filter_text = f"Filter: [b]{app.filter_kind}[/b]"
        arch_text = " | [reverse] ARCHIVED [/reverse]" if app.show_archived else ""

        return f"Entry Grid  |  Pg {pg}  Rows {rows}  Density {density}  {filter_text}{arch_text}  Search {search}"

    def on_mount(self) -> None:
        self.watch(self.app, "search_mode", self.refresh)
        self.watch(self.app, "selected_entry_id", self.refresh)
        self.watch(self.app, "filter_kind", self.refresh)
        self.watch(self.app, "show_archived", self.refresh)


class EntryDataTable(DataTable):
    """
    High-fidelity data table for entry browsing.
    """

    def on_mount(self) -> None:
        self.cursor_type = "row"
        self.add_columns("Sel", "Id", "Entry#", "Label", "Kind", "Meta", "Arch")
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

        # Map filter presets to kind lists
        kind_map = {
            "secrets": [
                "password",
                "totp",
                "ssh",
                "pgp",
                "nostr",
                "seed",
                "managed_account",
            ],
            "docs": ["document", "note"],
            "keys": ["ssh", "pgp", "nostr", "seed", "managed_account"],
            "2fa": ["totp"],
        }
        kinds = kind_map.get(app.filter_kind)

        entries = []
        # Use semantic search if requested and available
        if app.search_mode != "keyword" and "semantic" in app.services and query:
            try:
                results = app.services["semantic"].search(query, mode=app.search_mode)
                # results is list of {entry_id, kind, label, score, excerpt}
                for r in results:
                    eid = r["entry_id"]
                    # Fetch full entry to match table columns
                    entry = app.services["entry"].retrieve_entry(eid)
                    if entry:
                        kind_val = str(
                            entry.get("kind") or entry.get("type") or ""
                        ).lower()
                        # Filtering for semantic results (best effort)
                        if kinds and kind_val not in kinds:
                            continue
                        is_arch = bool(entry.get("archived", False))
                        if app.show_archived and not is_arch:
                            continue
                        if not app.show_archived and is_arch:
                            continue

                        from seedpass.core.entry_types import EntryType

                        try:
                            etype = EntryType(kind_val)
                        except ValueError:
                            etype = kind_val

                        entries.append(
                            (
                                eid,
                                entry.get("label", ""),
                                entry.get("username"),
                                entry.get("url"),
                                is_arch,
                                etype,
                            )
                        )
            except Exception as e:
                app.notify(f"Semantic search failed: {e}", severity="error")
                # Fallback to lexical
                entries = app.services["entry"].search_entries(
                    query,
                    kinds=kinds,
                    include_archived=app.show_archived,
                    archived_only=app.show_archived,
                )
        else:
            # Fetch filtered data from standard service
            entries = app.services["entry"].search_entries(
                query,
                kinds=kinds,
                include_archived=app.show_archived,
                archived_only=app.show_archived,
            )

        for i, (eid, label, user, url, arch, kind) in enumerate(entries):
            marker = "▶" if eid == app.selected_entry_id else " "
            arch_status = "🔒" if arch else " "
            # 'Meta' column logic from mockup
            meta = user or url or ""

            self.add_row(
                marker,
                str(i + 1),
                f"#{eid}",
                label,
                kind.value,
                meta,
                arch_status,
                key=str(eid),
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
        background: #999999;
    }
    #grid-divider {
        color: #000000;
        height: 1;
        padding: 0;
        background: black;
    }
    #entry-data-table {
        background: #999999;
        color: #000000;
        border: none;
        height: 1fr;
    }
    #entry-data-table > .datatable--header {
        background: #999999;
        color: #000000;
        text-style: bold;
    }
    #entry-data-table > .datatable--cursor {
        background: #000000;
        color: #ffffff;
    }
    """
