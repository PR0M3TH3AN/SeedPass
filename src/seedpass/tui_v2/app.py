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

    from textual.app import App, ComposeResult
    from textual.containers import Horizontal, Vertical
    from textual.reactive import reactive
    from textual.widgets import Footer, Header, Input, Label, ListItem, ListView, Static

    try:
        from textual.widgets import TextArea
    except Exception:  # pragma: no cover - runtime fallback for older textual
        TextArea = None

    class EntryListItem(ListItem):
        def __init__(self, entry_index: int, text: str) -> None:
            super().__init__(Label(text))
            self.entry_index = int(entry_index)

    class SeedPassTuiV2(App[None]):
        CSS = """
        #body { height: 1fr; }
        #status { height: 1; padding: 0 1; }
        #left { width: 30; border: solid $primary; padding: 1; }
        #center { width: 1fr; border: solid $primary; padding: 1; }
        #right { width: 1fr; border: solid $primary; padding: 1; }
        #search { margin-bottom: 1; }
        #entry-list { height: 1fr; }
        #entry-detail { height: 1fr; overflow: auto; }
        #right-view { height: 1fr; }
        #right-editor { height: 1fr; }
        #doc-edit-label { margin-bottom: 1; }
        #doc-edit-file-type { margin-bottom: 1; }
        #doc-edit-tags { margin-bottom: 1; }
        #doc-edit-help { margin-top: 1; }
        #doc-edit-content { height: 1fr; }
        #doc-edit-content-single { height: 1fr; }
        .hidden { display: none; }
        """
        BINDINGS = [
            ("q", "quit", "Quit"),
            ("r", "refresh", "Refresh"),
            ("slash", "focus_search", "Search"),
            ("f", "cycle_filter", "Filter"),
            ("a", "toggle_archive", "Archive/Restore"),
            ("e", "edit_document", "Edit Document"),
            ("ctrl+s", "save_document", "Save"),
            ("escape", "cancel_document_edit", "Cancel"),
        ]

        filter_kind: reactive[str] = reactive("all")
        editing_document: reactive[bool] = reactive(False)

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
                    with Vertical(id="right-view"):
                        yield Static("", id="entry-detail")
                    with Vertical(id="right-editor", classes="hidden"):
                        yield Input(placeholder="Document title", id="doc-edit-label")
                        yield Input(
                            placeholder="File extension (txt, md, py, ...)",
                            id="doc-edit-file-type",
                        )
                        yield Input(
                            placeholder="Tags (comma-separated)", id="doc-edit-tags"
                        )
                        if TextArea is not None:
                            yield TextArea("", id="doc-edit-content")
                        else:
                            yield Input(
                                placeholder="Document content",
                                id="doc-edit-content-single",
                            )
                        yield Static(
                            "Edit mode: Ctrl+S save, Esc cancel",
                            id="doc-edit-help",
                        )
            yield Static("Ready", id="status")
            yield Footer()

        def on_mount(self) -> None:
            self._service = None
            self._selected_entry_id: int | None = None
            self._selected_entry: dict[str, Any] | None = None
            self._last_query = ""
            self._entry_ids_in_view: list[int] = []
            try:
                self._service = (
                    entry_service_factory() if callable(entry_service_factory) else None
                )
            except Exception as exc:
                self._service = None
                self._set_status(f"Unable to initialize entry service: {exc}")
                self.query_one("#entry-detail", Static).update(
                    f"Unable to initialize entry service: {exc}"
                )
            self._update_filters_panel()
            self._load_entries()

        def _set_status(self, message: str) -> None:
            self.query_one("#status", Static).update(message)

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
                    "TUI v2 (Phase 2)",
                    fp_line,
                    "",
                    f"Active filter: {self.filter_kind}",
                    "",
                    "Navigation:",
                    "- / search",
                    "- f cycle kind filter",
                    "- r refresh",
                    "",
                    "Actions:",
                    "- a archive/restore",
                    "- e edit document",
                    "- Ctrl+S save doc",
                    "- Esc cancel edit",
                ]
            )
            self.query_one("#filters", Static).update(text)

        def _render_entry_label(
            self, idx: int, label: str, etype: str, archived: bool
        ) -> str:
            arch = " [archived]" if archived else ""
            return f"{idx:>4}  {etype:<15}  {label}{arch}"

        def _load_entries(self, query: str = "") -> None:
            self._last_query = query
            self._entry_ids_in_view = []
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
                self._set_status("Failed to load entries")
                return

            for idx, label, _username, _url, archived, etype in results:
                kind = getattr(etype, "value", str(etype))
                item = EntryListItem(
                    idx,
                    self._render_entry_label(idx, label, kind, bool(archived)),
                )
                self._entry_ids_in_view.append(int(idx))
                list_view.append(item)

            if len(results) == 0:
                self._selected_entry_id = None
                self._selected_entry = None
                self.query_one("#entry-detail", Static).update("No entries match.")
                self._set_status("No entries match current filter/search")
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
                    self._set_status(f"Entry {entry_index} not found")
                    return
                self._selected_entry_id = int(entry_index)
                self._selected_entry = dict(entry)
                body = json.dumps(entry, indent=2, sort_keys=True)
                self.query_one("#entry-detail", Static).update(body)
                self._set_status(f"Selected entry {entry_index}")
            except Exception as exc:
                self.query_one("#entry-detail", Static).update(
                    f"Failed to load entry {entry_index}: {exc}"
                )
                self._set_status(f"Failed to load entry {entry_index}")

        def _is_selected_document(self) -> bool:
            if not isinstance(self._selected_entry, dict):
                return False
            kind = str(
                self._selected_entry.get("kind") or self._selected_entry.get("type")
            )
            return kind == "document"

        def _set_document_editor_visible(self, visible: bool) -> None:
            view = self.query_one("#right-view", Vertical)
            editor = self.query_one("#right-editor", Vertical)
            if visible:
                view.add_class("hidden")
                editor.remove_class("hidden")
            else:
                editor.add_class("hidden")
                view.remove_class("hidden")
            self.editing_document = visible

        def _get_document_editor_text(self) -> str:
            if TextArea is not None:
                area = self.query_one("#doc-edit-content")
                return str(getattr(area, "text", ""))
            return self.query_one("#doc-edit-content-single", Input).value

        def _set_document_editor_text(self, content: str) -> None:
            if TextArea is not None:
                area = self.query_one("#doc-edit-content")
                if hasattr(area, "load_text"):
                    area.load_text(content)
                elif hasattr(area, "text"):
                    area.text = content
                return
            self.query_one("#doc-edit-content-single", Input).value = content

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

        def action_toggle_archive(self) -> None:
            if self._service is None or self._selected_entry_id is None:
                self._set_status("No entry selected")
                return
            if self.editing_document:
                self._set_status("Finish document edit before archive/restore")
                return

            try:
                archived = bool(
                    self._selected_entry and self._selected_entry.get("archived")
                )
                if archived:
                    self._service.restore_entry(self._selected_entry_id)
                    action = "restored"
                else:
                    self._service.archive_entry(self._selected_entry_id)
                    action = "archived"
                current_id = self._selected_entry_id
                self._load_entries(self._last_query)
                if current_id in self._entry_ids_in_view:
                    self._show_entry(current_id)
                self._set_status(f"Entry {current_id} {action}")
            except Exception as exc:
                self._set_status(f"Archive/restore failed: {exc}")

        def action_edit_document(self) -> None:
            if self._service is None:
                self._set_status("Entry service unavailable")
                return
            if self._selected_entry_id is None or not self._is_selected_document():
                self._set_status("Select a document entry to edit")
                return
            if self.editing_document:
                self._set_status("Document editor already open")
                return

            entry = self._selected_entry or {}
            self.query_one("#doc-edit-label", Input).value = str(entry.get("label", ""))
            self.query_one("#doc-edit-file-type", Input).value = str(
                entry.get("file_type", "txt")
            )
            tags = entry.get("tags")
            if isinstance(tags, list):
                tags_text = ", ".join(str(tag) for tag in tags)
            else:
                tags_text = ""
            self.query_one("#doc-edit-tags", Input).value = tags_text
            self._set_document_editor_text(str(entry.get("content", "")))
            self._set_document_editor_visible(True)
            if TextArea is not None:
                self.query_one("#doc-edit-content").focus()
            else:
                self.query_one("#doc-edit-content-single", Input).focus()
            self._set_status(f"Editing document {self._selected_entry_id}")

        def action_save_document(self) -> None:
            if not self.editing_document:
                self._set_status("Document editor not active")
                return
            if self._service is None or self._selected_entry_id is None:
                self._set_status("No document selected")
                return

            label = self.query_one("#doc-edit-label", Input).value.strip()
            file_type = (
                self.query_one("#doc-edit-file-type", Input).value.strip().lstrip(".")
            )
            tags_raw = self.query_one("#doc-edit-tags", Input).value.strip()
            tags = [part.strip() for part in tags_raw.split(",") if part.strip()]
            content = self._get_document_editor_text()

            try:
                self._service.modify_entry(
                    self._selected_entry_id,
                    label=label or None,
                    content=content,
                    file_type=file_type or None,
                    tags=tags,
                )
                current_id = self._selected_entry_id
                self._set_document_editor_visible(False)
                self._load_entries(self._last_query)
                if current_id in self._entry_ids_in_view:
                    self._show_entry(current_id)
                self._set_status(f"Saved document {current_id}")
            except Exception as exc:
                self._set_status(f"Failed to save document: {exc}")

        def action_cancel_document_edit(self) -> None:
            if not self.editing_document:
                return
            self._set_document_editor_visible(False)
            self._set_status("Canceled document edit")

        def on_input_submitted(self, event: Input.Submitted) -> None:
            if event.input.id == "search":
                if self.editing_document:
                    self._set_status("Finish document edit before searching")
                    return
                self._load_entries(query=event.value.strip())

        def on_list_view_selected(self, event: ListView.Selected) -> None:
            if self.editing_document:
                self._set_status("Finish document edit before selecting another entry")
                return
            item = event.item
            if isinstance(item, EntryListItem):
                self._show_entry(item.entry_index)

    SeedPassTuiV2().run()
    return True
