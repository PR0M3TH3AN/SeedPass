from __future__ import annotations
from typing import Any
from types import SimpleNamespace
from textual.app import ComposeResult
from textual.widgets import Static, DataTable, Button
from textual.containers import Horizontal
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
        m = app.search_mode
        keyword = f"[b](KEYWORD)[/b]" if m == "keyword" else "keyword"
        hybrid = f"[b](HYBRID)[/b]" if m == "hybrid" else "hybrid"
        semantic = f"[b](SEMANTIC)[/b]" if m == "semantic" else "semantic"

        search = f"{keyword} {hybrid} {semantic}"
        filter_text = f"Filter: [b]{app.filter_kind}[/b]"
        sort_text = f"Sort: [b]{app.search_sort}[/b]"
        query_text = (
            f' Query: [b]"{app.search_query}"[/b]' if str(app.search_query).strip() else ""
        )
        arch_text = " | [reverse] ARCHIVED [/reverse]" if app.show_archived else ""

        return (
            f"Entry Grid  |  Pg {pg}  Rows {rows}  Density {density}  "
            f"{filter_text}  {sort_text}{arch_text}{query_text}  Search {search}"
        )

    def on_mount(self) -> None:
        self.watch(self.app, "search_mode", self.refresh)
        self.watch(self.app, "selected_entry_id", self.refresh)
        self.watch(self.app, "filter_kind", self.refresh)
        self.watch(self.app, "show_archived", self.refresh)
        self.watch(self.app, "search_sort", self.refresh)
        self.watch(self.app, "search_query", self.refresh)


class GridToolbar(Horizontal):
    """Explicit filter/sort/search-mode controls for the main grid."""

    DEFAULT_CSS = """
    GridToolbar {
        height: 3;
        background: #d9d9d9;
        color: #000000;
        padding: 0 1;
    }
    GridToolbar Button {
        min-width: 8;
        width: auto;
        margin-right: 1;
        height: 1;
    }
    """

    def compose(self) -> ComposeResult:
        yield Button("All", id="grid-filter-all")
        yield Button("Secrets", id="grid-filter-secrets")
        yield Button("Docs", id="grid-filter-docs")
        yield Button("Keys", id="grid-filter-keys")
        yield Button("2FA", id="grid-filter-2fa")
        yield Button("Archived", id="grid-toggle-archived")
        yield Button("Keyword", id="grid-mode-keyword")
        yield Button("Hybrid", id="grid-mode-hybrid")
        yield Button("Semantic", id="grid-mode-semantic")
        yield Button("Relevance", id="grid-sort-relevance")
        yield Button("Recent", id="grid-sort-modified_desc")
        yield Button("Label", id="grid-sort-label_asc")
        yield Button("Linked", id="grid-sort-most_linked")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""
        if button_id.startswith("grid-filter-"):
            self.app.action_set_kind_filter(button_id.removeprefix("grid-filter-"))
            return
        if button_id == "grid-toggle-archived":
            self.app.action_toggle_archived_view()
            return
        if button_id.startswith("grid-mode-"):
            self.app.action_set_search_mode(button_id.removeprefix("grid-mode-"))
            return
        if button_id.startswith("grid-sort-"):
            self.app.action_set_search_sort(button_id.removeprefix("grid-sort-"))


class EntryDataTable(DataTable):
    """
    High-fidelity data table for entry browsing.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._suppress_next_highlight = True

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

    def _refresh_data(self, query: str | None = None) -> None:
        self.clear()
        app = self.app
        if "entry" not in app.services:
            return
        active_query = app.search_query if query is None else query
        if app.selected_entry_id is None:
            self._suppress_next_highlight = True

        # Map filter presets to kind lists
        kind_map = {
            "secrets": [
                "password",
                "stored_password",
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
        if "search" in app.services:
            try:
                results = app.services["search"].search(
                    active_query,
                    kinds=kinds,
                    include_archived=app.show_archived,
                    archived_only=app.show_archived,
                    mode=app.search_mode,
                    sort=app.search_sort,
                )
                for result in results:
                    try:
                        kind_val = str(result.get("kind", "")).lower()
                        entry_id = int(result.get("entry_id", 0))
                    except Exception:
                        continue
                    entries.append(
                        (
                            entry_id,
                            str(result.get("label", "")),
                            None,
                            str(result.get("meta", "")) or None,
                            bool(result.get("archived", False)),
                            SimpleNamespace(value=kind_val),
                        )
                    )
            except Exception as e:
                app.notify(f"Search failed: {e}", severity="error")
                entries = []
        # Fallback to direct semantic search if requested and available
        elif app.search_mode != "keyword" and "semantic" in app.services and active_query:
            try:
                results = app.services["semantic"].search(active_query, mode=app.search_mode)
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
                    active_query,
                    kinds=kinds,
                    include_archived=app.show_archived,
                    archived_only=app.show_archived,
                )
        else:
            # Fetch filtered data from standard service
            entries = app.services["entry"].search_entries(
                active_query,
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
            if self._suppress_next_highlight and self.app.selected_entry_id is None:
                self._suppress_next_highlight = False
                return
            try:
                self.app.selected_entry_id = int(rk)
            except ValueError:
                pass

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle explicit entry selection (Enter)."""
        rk = str(event.row_key.value) if event.row_key else None
        if rk:
            self._suppress_next_highlight = False
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
        yield GridToolbar()
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
