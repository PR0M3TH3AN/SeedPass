from __future__ import annotations

import importlib.util
import json
from typing import Any


def check_tui2_runtime() -> dict[str, Any]:
    """Return runtime capability diagnostics for TUI v2."""
    textual_available = importlib.util.find_spec("textual") is not None
    return {
        "status": "ok" if textual_available else "unavailable",
        "backend": "textual",
        "textual_available": textual_available,
        "message": (
            "Textual runtime available."
            if textual_available
            else "Textual is not installed. Install `textual` to run tui2."
        ),
    }


def launch_tui2(
    *,
    fingerprint: str | None = None,
    entry_service_factory: Any | None = None,
) -> bool:
    """Launch TUI v2 when runtime dependencies are available.

    Returns ``True`` when launch succeeds, ``False`` when runtime is unavailable.
    """
    runtime = check_tui2_runtime()
    if not runtime["textual_available"]:
        return False

    # Textual shell (phase 1: read-only list/search/details).
    from textual.app import App, ComposeResult
    from textual.containers import Horizontal, Vertical
    from textual.reactive import reactive
    from textual.widgets import Footer, Header, Input, Label, ListItem, ListView, Static

    class EntryListItem(ListItem):
        def __init__(self, entry_index: int, text: str) -> None:
            super().__init__(Label(text))
            self.entry_index = int(entry_index)

    class SeedPassTuiV2(App[None]):
        CSS = """
        #body { height: 1fr; }
        #left { width: 28; border: solid $primary; padding: 1; }
        #center { width: 1fr; border: solid $primary; padding: 1; }
        #right { width: 1fr; border: solid $primary; padding: 1; }
        #search { margin-bottom: 1; }
        #entry-list { height: 1fr; }
        #entry-detail { height: 1fr; overflow: auto; }
        """
        BINDINGS = [("q", "quit", "Quit")]
        BINDINGS += [
            ("r", "refresh", "Refresh"),
            ("slash", "focus_search", "Search"),
            ("f", "cycle_filter", "Filter"),
        ]
        filter_kind: reactive[str] = reactive("all")

        def compose(self) -> ComposeResult:
            yield Header(show_clock=True)
            with Horizontal(id="body"):
                with Vertical(id="left"):
                    yield Static("", id="filters")
                with Vertical(id="center"):
                    yield Input(
                        placeholder="Search entries (Enter to apply)", id="search"
                    )
                    yield ListView(id="entry-list")
                with Vertical(id="right"):
                    yield Static("", id="entry-detail")
            yield Footer()

        def on_mount(self) -> None:
            try:
                self._service = (
                    entry_service_factory() if callable(entry_service_factory) else None
                )
            except Exception as exc:
                self._service = None
                self.query_one("#entry-detail", Static).update(
                    f"Unable to initialize entry service: {exc}"
                )
            self._update_filters_panel()
            self._load_entries()

        def _current_filter_kinds(self) -> list[str] | None:
            if self.filter_kind == "all":
                return None
            return [self.filter_kind]

        def _update_filters_panel(self) -> None:
            fp_line = (
                f"Fingerprint: {fingerprint}"
                if fingerprint
                else "Fingerprint: (default)"
            )
            text = "\n".join(
                [
                    "TUI v2 (Phase 1)",
                    fp_line,
                    "",
                    f"Active filter: {self.filter_kind}",
                    "Press 'f' to cycle filter",
                    "Press '/' to focus search",
                    "Press 'r' to refresh",
                    "",
                    "Planned next:",
                    "- document editor pane",
                    "- graph links pane",
                ]
            )
            self.query_one("#filters", Static).update(text)

        def _render_entry_label(
            self, idx: int, label: str, etype: str, archived: bool
        ) -> str:
            arch = " [archived]" if archived else ""
            return f"{idx:>4}  {etype:<15}  {label}{arch}"

        def _load_entries(self, query: str = "") -> None:
            list_view = self.query_one("#entry-list", ListView)
            list_view.clear()
            if self._service is None:
                self.query_one("#entry-detail", Static).update(
                    "Entry service unavailable in this runtime."
                )
                return

            try:
                results = self._service.search_entries(
                    query, kinds=self._current_filter_kinds()
                )
            except Exception as exc:
                self.query_one("#entry-detail", Static).update(
                    f"Failed to load entries: {exc}"
                )
                return

            for idx, label, _username, _url, archived, etype in results:
                kind = getattr(etype, "value", str(etype))
                item = EntryListItem(
                    idx,
                    self._render_entry_label(idx, label, kind, bool(archived)),
                )
                list_view.append(item)

            if len(results) == 0:
                self.query_one("#entry-detail", Static).update("No entries match.")
            else:
                if list_view.children:
                    first = list_view.children[0]
                    if isinstance(first, EntryListItem):
                        self._show_entry(first.entry_index)

        def _show_entry(self, entry_index: int) -> None:
            if self._service is None:
                return
            try:
                entry = self._service.retrieve_entry(entry_index)
                if not isinstance(entry, dict):
                    self.query_one("#entry-detail", Static).update("Entry not found.")
                    return
                body = json.dumps(entry, indent=2, sort_keys=True)
                self.query_one("#entry-detail", Static).update(body)
            except Exception as exc:
                self.query_one("#entry-detail", Static).update(
                    f"Failed to load entry {entry_index}: {exc}"
                )

        def action_refresh(self) -> None:
            search = self.query_one("#search", Input).value
            self._update_filters_panel()
            self._load_entries(query=search)

        def action_focus_search(self) -> None:
            self.query_one("#search", Input).focus()

        def action_cycle_filter(self) -> None:
            order = [
                "all",
                "password",
                "totp",
                "document",
                "key_value",
                "ssh",
                "pgp",
                "nostr",
                "seed",
                "managed_account",
            ]
            idx = order.index(self.filter_kind) if self.filter_kind in order else 0
            self.filter_kind = order[(idx + 1) % len(order)]
            self.action_refresh()

        def on_input_submitted(self, event: Input.Submitted) -> None:
            if event.input.id == "search":
                self._load_entries(query=event.value.strip())

        def on_list_view_selected(self, event: ListView.Selected) -> None:
            item = event.item
            if isinstance(item, EntryListItem):
                self._show_entry(item.entry_index)

    SeedPassTuiV2().run()
    return True
