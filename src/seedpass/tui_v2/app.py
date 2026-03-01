from __future__ import annotations

import importlib.util
import json
import shlex
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


def parse_palette_command(command: str) -> tuple[str, list[str]]:
    """Parse a palette command into ``(cmd, args)``."""
    raw = command.strip()
    if not raw:
        raise ValueError("Palette: command required")
    try:
        parts = shlex.split(raw)
    except ValueError as exc:
        raise ValueError(f"Palette parse error: {exc}") from exc
    if not parts:
        raise ValueError("Palette: command required")
    return parts[0].lower(), parts[1:]


def pagination_window(
    total_rows: int, page_size: int, page_index: int
) -> tuple[int, int, int, int]:
    """Return normalized pagination tuple.

    Returns ``(normalized_page_index, start, end, total_pages)``.
    """
    if page_size <= 0:
        raise ValueError("page_size must be > 0")
    total = max(0, int(total_rows))
    total_pages = 1 if total == 0 else (total + page_size - 1) // page_size
    page = min(max(0, int(page_index)), total_pages - 1)
    start = page * page_size
    end = min(total, start + page_size)
    return page, start, end, total_pages


def truncate_entry_for_display(
    entry: dict[str, Any], content_limit: int
) -> dict[str, Any]:
    """Return an entry payload suitable for responsive display in TUI details."""
    payload = dict(entry)
    content = payload.get("content")
    if content_limit <= 0:
        return payload
    if isinstance(content, str) and len(content) > content_limit:
        head = content[:content_limit]
        payload["content"] = (
            f"{head}\n\n...[truncated {len(content) - len(head)} chars]"
        )
        payload["content_truncated"] = True
    return payload


def launch_tui2(
    *,
    fingerprint: str | None = None,
    entry_service_factory: Any | None = None,
    app_hook: Any | None = None,
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
        RESULT_PAGE_SIZE = 200
        DETAIL_CONTENT_PREVIEW_LIMIT = 4000

        CSS = """
        #command-palette {
            height: 2;
            margin: 0 1 1 1;
            border: solid $secondary;
            background: $panel;
        }
        #body { height: 1fr; }
        #status {
            height: 1;
            padding: 0 1;
            border: heavy $primary;
            background: $panel;
        }
        #left { width: 34; border: solid $primary; padding: 1; background: $panel; }
        #center { width: 1fr; border: solid $primary; padding: 1; background: $panel; }
        #right { width: 1fr; border: solid $primary; padding: 1; background: $panel; }
        #search { margin-bottom: 1; }
        #quick-jump { margin-bottom: 1; }
        #entry-list { height: 1fr; }
        #entry-detail {
            height: 1fr;
            overflow: auto;
            border: solid $boost;
            padding: 1;
        }
        #link-detail {
            height: 12;
            overflow: auto;
            border: solid $accent;
            padding: 1;
            margin-top: 1;
        }
        #right-view { height: 1fr; }
        #right-editor { height: 1fr; }
        #doc-edit-label { margin-bottom: 1; }
        #doc-edit-file-type { margin-bottom: 1; }
        #doc-edit-tags { margin-bottom: 1; }
        #doc-edit-help { margin-top: 1; }
        #doc-edit-content { height: 1fr; }
        #doc-edit-content-single { height: 1fr; }
        #help-overlay {
            layer: overlay;
            dock: top;
            margin: 1 2;
            border: solid $warning;
            padding: 1;
            background: $surface;
        }
        #activity {
            height: 12;
            border: solid $secondary;
            padding: 1;
            margin-top: 1;
            overflow: auto;
        }
        .pane-focus { border: heavy $success; }
        .hidden { display: none; }
        """
        BINDINGS = [
            ("q", "quit", "Quit"),
            ("r", "refresh", "Refresh"),
            ("x", "retry_last_error", "Retry"),
            ("question_mark", "toggle_help", "Help"),
            ("slash", "focus_search", "Search"),
            ("j", "focus_jump", "Jump"),
            ("1", "focus_left", "Left"),
            ("2", "focus_center", "Center"),
            ("3", "focus_right", "Right"),
            ("f", "cycle_filter", "Filter"),
            ("p", "prev_page", "Prev Page"),
            ("n", "next_page", "Next Page"),
            ("l", "cycle_link_filter", "Link Filter"),
            ("[", "prev_link", "Prev Link"),
            ("]", "next_link", "Next Link"),
            ("o", "open_link_target", "Open Link"),
            ("a", "toggle_archive", "Archive/Restore"),
            ("e", "edit_document", "Edit Document"),
            ("ctrl+s", "save_document", "Save"),
            ("ctrl+p", "open_palette", "Palette"),
            ("escape", "cancel_document_edit", "Cancel"),
        ]

        filter_kind: reactive[str] = reactive("all")
        link_relation_filter: reactive[str] = reactive("all")
        editing_document: reactive[bool] = reactive(False)
        palette_open: reactive[bool] = reactive(False)
        help_open: reactive[bool] = reactive(False)

        def compose(self) -> ComposeResult:
            yield Header(show_clock=True)
            yield Input(
                placeholder=(
                    "Command palette: help | open <id> | search <q> | "
                    "filter <kind> | archive | restore | "
                    "link-add <target> [relation] [note] | "
                    "link-rm <target> [relation] | "
                    "link-filter <relation|all> | link-next | link-prev | link-open | "
                    "page-next | page-prev | page <n> | retry"
                ),
                id="command-palette",
                classes="hidden",
            )
            yield Static("", id="help-overlay", classes="hidden")
            with Horizontal(id="body"):
                with Vertical(id="left"):
                    yield Static("", id="filters")
                    yield Static("", id="activity")
                with Vertical(id="center"):
                    yield Input(
                        placeholder="Search entries (Enter to apply)", id="search"
                    )
                    yield Input(placeholder="Jump to entry id (Enter)", id="quick-jump")
                    yield ListView(id="entry-list")
                with Vertical(id="right"):
                    with Vertical(id="right-view"):
                        yield Static("", id="entry-detail")
                        yield Static("", id="link-detail")
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
            self._all_results: list[tuple[Any, ...]] = []
            self._result_page = 0
            self._current_links: list[dict[str, Any]] = []
            self._current_link_cursor = 0
            self._last_error: str | None = None
            self._retry_action: Any | None = None
            self._activity_log: list[str] = []
            self._focus_pane = "center"
            self._doc_dirty = False
            self._doc_snapshot: dict[str, Any] = {}
            self._last_status_message = ""
            try:
                self._service = (
                    entry_service_factory() if callable(entry_service_factory) else None
                )
            except Exception as exc:
                self._service = None
                self._record_failure(
                    "Unable to initialize entry service",
                    exc,
                    retry=self._retry_initialize_service,
                    hint="Press 'x' to retry initialization.",
                )
                self.query_one("#entry-detail", Static).update(
                    f"Unable to initialize entry service: {exc}"
                )
            self._update_filters_panel()
            self._update_help_overlay()
            self._update_activity_panel()
            self._apply_focus_style()
            self._load_entries()

        def _set_status(self, message: str) -> None:
            if message == self._last_status_message:
                return
            self._last_status_message = message
            mode = (
                "PALETTE"
                if self.palette_open
                else ("EDIT" if self.editing_document else "VIEW")
            )
            text = f"[{mode} | {self._focus_pane.upper()}] {message}"
            self.query_one("#status", Static).update(text)
            self._log_activity(message)

        def _log_activity(self, message: str) -> None:
            msg = message.strip()
            if not msg:
                return
            self._activity_log.append(msg)
            self._activity_log = self._activity_log[-5:]
            self._update_activity_panel()

        def _update_activity_panel(self) -> None:
            if not self._activity_log:
                text = "Activity Log\n\nNo actions yet."
            else:
                lines = ["Activity Log", ""]
                for i, item in enumerate(reversed(self._activity_log), start=1):
                    short = item if len(item) <= 88 else f"{item[:85]}..."
                    lines.append(f"{i}. {short}")
                text = "\n".join(lines)
            self.query_one("#activity", Static).update(text)

        def _update_help_overlay(self) -> None:
            box = self.query_one("#help-overlay", Static)
            if not self.help_open:
                box.add_class("hidden")
                return
            box.remove_class("hidden")
            text = "\n".join(
                [
                    "TUI v2 Quick Help  (Esc to close)",
                    "",
                    "Core      : / search   j jump-id   p/n page   r refresh",
                    "Modes     : Ctrl+P palette   e edit-doc   Ctrl+S save   Esc cancel/close",
                    "Graph     : l relation filter   brackets link select   o open link target",
                    "Resilience: x retry last error",
                    "Pane Focus: 1 left   2 center   3 right",
                    "",
                    "Palette examples",
                    "help | filter document | open 12 | link-add 7 references note",
                ]
            )
            box.update(text)

        def _apply_focus_style(self) -> None:
            for pane_id in ("left", "center", "right"):
                pane = self.query_one(f"#{pane_id}", Vertical)
                if pane_id == self._focus_pane:
                    pane.add_class("pane-focus")
                else:
                    pane.remove_class("pane-focus")

        def _refresh_doc_edit_help(self) -> None:
            marker = "*" if self._doc_dirty else "clean"
            self.query_one("#doc-edit-help", Static).update(
                f"Edit mode [{marker}]: Ctrl+S save, Esc cancel"
            )

        def _record_failure(
            self,
            context: str,
            exc: Exception,
            *,
            retry: Any | None = None,
            hint: str = "",
        ) -> None:
            self._last_error = f"{context}: {exc}"
            self._retry_action = retry
            suffix = f" {hint}" if hint else ""
            self._set_status(f"{self._last_error}.{suffix}")

        def _clear_failure(self) -> None:
            self._last_error = None
            self._retry_action = None

        def _retry_initialize_service(self) -> None:
            try:
                self._service = (
                    entry_service_factory() if callable(entry_service_factory) else None
                )
            except Exception as exc:
                self._record_failure(
                    "Unable to initialize entry service",
                    exc,
                    retry=self._retry_initialize_service,
                    hint="Press 'x' to retry initialization.",
                )
                return
            self._clear_failure()
            self._set_status("Entry service initialized")
            self._load_entries(self._last_query, reset_page=False)

        def _current_filter_kinds(self) -> list[str] | None:
            if self.filter_kind == "all":
                return None
            return [self.filter_kind]

        def _selected_summary(self) -> str:
            if (
                not isinstance(self._selected_entry, dict)
                or self._selected_entry_id is None
            ):
                return "Selected: (none)"
            kind = str(
                self._selected_entry.get("kind")
                or self._selected_entry.get("type")
                or "unknown"
            )
            label = str(self._selected_entry.get("label", ""))
            return f"Selected: #{self._selected_entry_id} [{kind}] {label}"

        def _update_filters_panel(self) -> None:
            fp_line = (
                f"Fingerprint: {fingerprint}"
                if fingerprint
                else "Fingerprint: (default)"
            )
            text = "\n".join(
                [
                    "SeedPass TUI v2",
                    fp_line,
                    "",
                    self._selected_summary(),
                    f"Filter : {self.filter_kind}",
                    f"Links  : {self.link_relation_filter}",
                    (
                        f"Results: {len(self._all_results)} | "
                        f"Page: {self._result_page + 1}/{self._total_pages()}"
                    ),
                    "",
                    "Nav",
                    "- / search",
                    "- j jump to id",
                    "- f cycle kind filter",
                    "- p/n prev/next page",
                    "- 1/2/3 focus pane",
                    "- ? help overlay",
                    "- r refresh",
                    "- x retry last error",
                    "",
                    "Actions",
                    "- a archive/restore",
                    "- e edit document",
                    "- Ctrl+S save doc",
                    "- Ctrl+P command palette",
                    "- l cycle link relation",
                    "- [ / ] select link",
                    "- o open link target",
                    "- Esc cancel/close",
                ]
            )
            self.query_one("#filters", Static).update(text)

        def _render_entry_label(
            self, idx: int, label: str, etype: str, archived: bool
        ) -> str:
            arch = " [archived]" if archived else ""
            return f"{idx:>4}  {etype:<15}  {label}{arch}"

        def _total_pages(self) -> int:
            _page, _start, _end, total_pages = pagination_window(
                len(self._all_results), self.RESULT_PAGE_SIZE, self._result_page
            )
            return total_pages

        def _render_current_page(self, *, preserve_selected: bool = True) -> None:
            self._entry_ids_in_view = []
            list_view = self.query_one("#entry-list", ListView)
            list_view.clear()
            total = len(self._all_results)
            if total == 0:
                self._selected_entry_id = None
                self._selected_entry = None
                self.query_one("#entry-detail", Static).update("No entries match.")
                self.query_one("#link-detail", Static).update(
                    "Links: select an entry first."
                )
                self._current_links = []
                self._current_link_cursor = 0
                self._set_status("No entries match current filter/search")
                self._update_filters_panel()
                return

            self._result_page, start, end, _total_pages = pagination_window(
                total, self.RESULT_PAGE_SIZE, self._result_page
            )
            page_rows = self._all_results[start:end]
            for idx, label, _username, _url, archived, etype in page_rows:
                kind = getattr(etype, "value", str(etype))
                item = EntryListItem(
                    idx,
                    self._render_entry_label(idx, label, kind, bool(archived)),
                )
                self._entry_ids_in_view.append(int(idx))
                list_view.append(item)

            self._update_filters_panel()
            chosen_id = None
            if preserve_selected and self._selected_entry_id in self._entry_ids_in_view:
                chosen_id = self._selected_entry_id
            elif self._entry_ids_in_view:
                chosen_id = self._entry_ids_in_view[0]
            if chosen_id is not None:
                self._show_entry(chosen_id)

        def _entry_detail_text(self, entry: dict[str, Any]) -> str:
            payload = truncate_entry_for_display(
                entry, self.DETAIL_CONTENT_PREVIEW_LIMIT
            )
            entry_id = (
                self._selected_entry_id
                if self._selected_entry_id is not None
                else payload.get("id", "?")
            )
            kind = payload.get("kind") or payload.get("type") or "unknown"
            header = f"Entry #{entry_id}  [{kind}]"
            return f"{header}\n{'-' * len(header)}\n{json.dumps(payload, indent=2, sort_keys=True)}"

        def _load_entries(self, query: str = "", *, reset_page: bool = False) -> None:
            self._last_query = query
            if self._service is None:
                self.query_one("#entry-detail", Static).update(
                    "Entry service unavailable in this runtime."
                )
                self.query_one("#link-detail", Static).update("Links unavailable.")
                self._all_results = []
                self._result_page = 0
                self._current_links = []
                self._current_link_cursor = 0
                self._update_filters_panel()
                return

            try:
                results = self._service.search_entries(
                    query, kinds=self._current_filter_kinds()
                )
            except Exception as exc:
                self.query_one("#entry-detail", Static).update(
                    f"Failed to load entries: {exc}"
                )
                self.query_one("#link-detail", Static).update("Links unavailable.")
                self._all_results = []
                self._result_page = 0
                self._current_links = []
                self._current_link_cursor = 0
                self._update_filters_panel()
                self._record_failure(
                    "Failed to load entries",
                    exc,
                    retry=lambda: self._load_entries(
                        self._last_query, reset_page=False
                    ),
                    hint="Press 'x' to retry.",
                )
                return

            self._all_results = list(results)
            self._clear_failure()
            if reset_page:
                self._result_page = 0
            self._render_current_page(preserve_selected=not reset_page)

        def _show_entry(self, entry_index: int) -> None:
            if self._service is None:
                return
            try:
                entry = self._service.retrieve_entry(entry_index)
                if not isinstance(entry, dict):
                    self.query_one("#entry-detail", Static).update("Entry not found.")
                    self.query_one("#link-detail", Static).update(
                        "Links: entry not found."
                    )
                    self._current_links = []
                    self._current_link_cursor = 0
                    self._set_status(f"Entry {entry_index} not found")
                    return
                self._selected_entry_id = int(entry_index)
                self._selected_entry = dict(entry)
                body = self._entry_detail_text(entry)
                self.query_one("#entry-detail", Static).update(body)
                self._update_links_panel()
                self._set_status(f"Selected entry {entry_index}")
            except Exception as exc:
                self.query_one("#entry-detail", Static).update(
                    f"Failed to load entry {entry_index}: {exc}"
                )
                self.query_one("#link-detail", Static).update("Links unavailable.")
                self._current_links = []
                self._current_link_cursor = 0
                self._record_failure(
                    f"Failed to load entry {entry_index}",
                    exc,
                    retry=lambda: self._show_entry(entry_index),
                    hint="Press 'x' to retry.",
                )

        def _update_links_panel(self) -> None:
            if self._service is None or self._selected_entry_id is None:
                self.query_one("#link-detail", Static).update(
                    "Links: select an entry first."
                )
                self._current_links = []
                self._current_link_cursor = 0
                return
            try:
                links = self._service.get_links(self._selected_entry_id)
            except Exception as exc:
                self.query_one("#link-detail", Static).update(
                    f"Links unavailable: {exc}"
                )
                self._current_links = []
                self._current_link_cursor = 0
                self._record_failure(
                    "Failed to load entry links",
                    exc,
                    retry=self._update_links_panel,
                    hint="Press 'x' to retry.",
                )
                return

            if self.link_relation_filter == "all":
                filtered = [lnk for lnk in links if isinstance(lnk, dict)]
            else:
                filtered = [
                    lnk
                    for lnk in links
                    if isinstance(lnk, dict)
                    and str(lnk.get("relation", "related_to")).lower()
                    == self.link_relation_filter
                ]
            self._current_links = filtered
            if self._current_link_cursor >= len(self._current_links):
                self._current_link_cursor = 0

            if not links:
                self.query_one("#link-detail", Static).update(
                    f"Links for #{self._selected_entry_id}\n\nNo graph links for this entry.\n"
                    "Use Ctrl+P and run: link-add <target_id> [relation] [note]"
                )
                return
            if not filtered:
                self.query_one("#link-detail", Static).update(
                    f"Links for #{self._selected_entry_id}\n\n"
                    f"Relation filter: {self.link_relation_filter}\n\n"
                    "No links match this relation filter.\n"
                    "Press 'l' to cycle relation filter."
                )
                return

            lines = [
                f"Links for #{self._selected_entry_id}",
                "",
                f"Relation filter: {self.link_relation_filter}",
                (
                    f"Selected link: {self._current_link_cursor + 1}/"
                    f"{len(self._current_links)}"
                ),
                "",
                "Format: relation -> target_id (note)",
                "",
            ]
            for i, link in enumerate(self._current_links):
                target = link.get("target")
                relation = link.get("relation", "related_to")
                note = str(link.get("note", "")).strip()
                prefix = ">" if i == self._current_link_cursor else " "
                if note:
                    lines.append(f"{prefix} {relation} -> {target} ({note})")
                else:
                    lines.append(f"{prefix} {relation} -> {target}")
            self.query_one("#link-detail", Static).update("\n".join(lines))
            self._clear_failure()

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
            self._focus_pane = "right"
            self._apply_focus_style()

        def _set_palette_visible(self, visible: bool) -> None:
            palette = self.query_one("#command-palette", Input)
            if visible:
                palette.remove_class("hidden")
                palette.focus()
            else:
                palette.value = ""
                palette.add_class("hidden")
            self.palette_open = visible
            self._update_help_overlay()

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

        def _mark_doc_dirty(self, dirty: bool = True) -> None:
            if not self.editing_document:
                return
            if self._doc_dirty == dirty:
                return
            self._doc_dirty = dirty
            self._refresh_doc_edit_help()

        def _run_palette_command(self, command: str) -> None:
            raw = command.strip()
            try:
                cmd, args = parse_palette_command(raw)
            except ValueError as exc:
                self._set_status(str(exc))
                return

            if cmd == "help":
                self._set_status(
                    "Palette commands: help, open, search, filter, archive, "
                    "restore, edit-doc, save-doc, cancel-edit, link-add, link-rm, "
                    "link-filter, link-next, link-prev, link-open, page-next, "
                    "page-prev, page <n>, retry, jump <id>"
                )
                return
            if cmd == "retry":
                self.action_retry_last_error()
                return

            if cmd == "open":
                if len(args) != 1:
                    self._set_status("Usage: open <entry_id>")
                    return
                try:
                    entry_id = int(args[0])
                except ValueError:
                    self._set_status("open requires integer entry_id")
                    return
                self._show_entry(entry_id)
                return
            if cmd == "jump":
                if len(args) != 1:
                    self._set_status("Usage: jump <entry_id>")
                    return
                try:
                    entry_id = int(args[0])
                except ValueError:
                    self._set_status("jump requires integer entry_id")
                    return
                self._show_entry(entry_id)
                return

            if cmd == "search":
                query = " ".join(args)
                self.query_one("#search", Input).value = query
                self._load_entries(query=query, reset_page=True)
                self._set_status(f"Applied search: {query}")
                return

            if cmd == "filter":
                if len(args) != 1:
                    self._set_status("Usage: filter <kind|all>")
                    return
                self.filter_kind = args[0].strip().lower()
                self._update_filters_panel()
                self._load_entries(query=self._last_query, reset_page=True)
                self._set_status(f"Applied filter: {self.filter_kind}")
                return

            if cmd in ("archive", "restore"):
                if self._service is None or self._selected_entry_id is None:
                    self._set_status("No entry selected")
                    return
                try:
                    if cmd == "archive":
                        self._service.archive_entry(self._selected_entry_id)
                        action = "archived"
                    else:
                        self._service.restore_entry(self._selected_entry_id)
                        action = "restored"
                    current_id = self._selected_entry_id
                    self._load_entries(self._last_query, reset_page=False)
                    if current_id in self._entry_ids_in_view:
                        self._show_entry(current_id)
                    self._clear_failure()
                    self._set_status(f"Entry {current_id} {action}")
                except Exception as exc:
                    self._record_failure(
                        f"{cmd} failed",
                        exc,
                        retry=lambda: self._run_palette_command(cmd),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "edit-doc":
                self.action_edit_document()
                return

            if cmd == "save-doc":
                self.action_save_document()
                return

            if cmd == "cancel-edit":
                self.action_cancel_document_edit()
                return

            if cmd == "link-add":
                if self._service is None or self._selected_entry_id is None:
                    self._set_status("No source entry selected")
                    return
                if len(args) < 1:
                    self._set_status(
                        "Usage: link-add <target_id> [relation] [note text]"
                    )
                    return
                try:
                    target = int(args[0])
                except ValueError:
                    self._set_status("link-add target_id must be an integer")
                    return
                relation = args[1] if len(args) >= 2 else "related_to"
                note = " ".join(args[2:]) if len(args) >= 3 else ""
                try:
                    self._service.add_link(
                        self._selected_entry_id,
                        target,
                        relation=relation,
                        note=note,
                    )
                    self._update_links_panel()
                    self._clear_failure()
                    self._set_status(
                        f"Link added: {self._selected_entry_id} {relation} {target}"
                    )
                except Exception as exc:
                    self._record_failure(
                        "link-add failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "link-rm":
                if self._service is None or self._selected_entry_id is None:
                    self._set_status("No source entry selected")
                    return
                if len(args) < 1:
                    self._set_status("Usage: link-rm <target_id> [relation]")
                    return
                try:
                    target = int(args[0])
                except ValueError:
                    self._set_status("link-rm target_id must be an integer")
                    return
                relation = args[1] if len(args) >= 2 else None
                try:
                    self._service.remove_link(
                        self._selected_entry_id,
                        target,
                        relation=relation,
                    )
                    self._update_links_panel()
                    self._clear_failure()
                    self._set_status(
                        f"Link removed: {self._selected_entry_id} -> {target}"
                    )
                except Exception as exc:
                    self._record_failure(
                        "link-rm failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "refresh":
                self.action_refresh()
                return
            if cmd == "page-next":
                self.action_next_page()
                return
            if cmd == "page-prev":
                self.action_prev_page()
                return
            if cmd == "page":
                if len(args) != 1:
                    self._set_status("Usage: page <page_number>")
                    return
                try:
                    page = int(args[0])
                except ValueError:
                    self._set_status("page requires integer page number")
                    return
                if page < 1:
                    self._set_status("page must be >= 1")
                    return
                self._result_page = min(page - 1, self._total_pages() - 1)
                self._render_current_page(preserve_selected=False)
                self._set_status(
                    f"Moved to page {self._result_page + 1}/{self._total_pages()}"
                )
                return
            if cmd == "link-filter":
                if len(args) != 1:
                    self._set_status("Usage: link-filter <relation|all>")
                    return
                relation = args[0].strip().lower() or "all"
                self.link_relation_filter = relation
                self._current_link_cursor = 0
                self._update_links_panel()
                self._set_status(f"Applied link relation filter: {relation}")
                return
            if cmd == "link-next":
                self.action_next_link()
                return
            if cmd == "link-prev":
                self.action_prev_link()
                return
            if cmd == "link-open":
                self.action_open_link_target()
                return

            self._set_status(f"Unknown command: {cmd}")

        def action_refresh(self) -> None:
            search = self.query_one("#search", Input).value
            self._update_filters_panel()
            self._load_entries(query=search, reset_page=False)

        def action_toggle_help(self) -> None:
            if self.palette_open:
                self._set_palette_visible(False)
            self.help_open = not self.help_open
            self._update_help_overlay()
            self._set_status("Help opened" if self.help_open else "Help closed")

        def action_focus_left(self) -> None:
            self._focus_pane = "left"
            self._apply_focus_style()
            self._set_status("Focused left pane")

        def action_focus_center(self) -> None:
            self._focus_pane = "center"
            self._apply_focus_style()
            self.query_one("#search", Input).focus()
            self._set_status("Focused center pane")

        def action_focus_right(self) -> None:
            self._focus_pane = "right"
            self._apply_focus_style()
            self._set_status("Focused right pane")

        def action_focus_jump(self) -> None:
            if self.editing_document:
                self._set_status("Finish document edit before jumping")
                return
            if self.palette_open:
                self._set_palette_visible(False)
            self._focus_pane = "center"
            self._apply_focus_style()
            self.query_one("#quick-jump", Input).focus()
            self._set_status("Focused jump-to-id input")

        def action_retry_last_error(self) -> None:
            retry = self._retry_action
            if retry is None:
                self._set_status("No retry action available")
                return
            try:
                retry()
            except Exception as exc:
                self._record_failure(
                    "Retry failed",
                    exc,
                    retry=retry,
                    hint="Press 'x' to retry again.",
                )

        def action_focus_search(self) -> None:
            if self.editing_document:
                self._set_status("Finish document edit before searching")
                return
            if self.palette_open:
                self._set_palette_visible(False)
            self._focus_pane = "center"
            self._apply_focus_style()
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
            self._load_entries(query=self._last_query, reset_page=True)
            self._set_status(f"Applied filter: {self.filter_kind}")

        def action_next_page(self) -> None:
            if not self._all_results:
                self._set_status("No entries loaded")
                return
            if self._result_page >= self._total_pages() - 1:
                self._set_status("Already on last page")
                return
            self._result_page += 1
            self._render_current_page(preserve_selected=False)
            self._set_status(f"Page {self._result_page + 1}/{self._total_pages()}")

        def action_prev_page(self) -> None:
            if not self._all_results:
                self._set_status("No entries loaded")
                return
            if self._result_page <= 0:
                self._set_status("Already on first page")
                return
            self._result_page -= 1
            self._render_current_page(preserve_selected=False)
            self._set_status(f"Page {self._result_page + 1}/{self._total_pages()}")

        def action_cycle_link_filter(self) -> None:
            if self._service is None or self._selected_entry_id is None:
                self._set_status("Select an entry before filtering links")
                return
            if self.editing_document:
                self._set_status("Finish document edit before link operations")
                return
            relation_order = [
                "all",
                "related_to",
                "depends_on",
                "references",
                "contains",
                "derived_from",
            ]
            idx = (
                relation_order.index(self.link_relation_filter)
                if self.link_relation_filter in relation_order
                else 0
            )
            self.link_relation_filter = relation_order[(idx + 1) % len(relation_order)]
            self._current_link_cursor = 0
            self._update_links_panel()
            self._set_status(f"Link relation filter: {self.link_relation_filter}")

        def action_next_link(self) -> None:
            if not self._current_links:
                self._set_status("No links to select")
                return
            self._current_link_cursor = (self._current_link_cursor + 1) % len(
                self._current_links
            )
            self._update_links_panel()
            self._set_status(
                f"Selected link {self._current_link_cursor + 1}/{len(self._current_links)}"
            )

        def action_prev_link(self) -> None:
            if not self._current_links:
                self._set_status("No links to select")
                return
            self._current_link_cursor = (self._current_link_cursor - 1) % len(
                self._current_links
            )
            self._update_links_panel()
            self._set_status(
                f"Selected link {self._current_link_cursor + 1}/{len(self._current_links)}"
            )

        def action_open_link_target(self) -> None:
            if not self._current_links:
                self._set_status("No links to open")
                return
            link = self._current_links[self._current_link_cursor]
            target = link.get("target")
            try:
                target_id = int(target)
            except Exception:
                self._set_status(f"Invalid link target: {target}")
                return
            self._show_entry(target_id)
            self._set_status(f"Opened linked entry {target_id}")

        def action_open_palette(self) -> None:
            if self.editing_document:
                self._set_status("Finish document edit before opening palette")
                return
            if self.help_open:
                self.help_open = False
                self._update_help_overlay()
            self._set_palette_visible(not self.palette_open)
            self._focus_pane = "center"
            self._apply_focus_style()
            if self.palette_open:
                self._set_status("Palette opened")
            else:
                self._set_status("Palette closed")

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
                self._clear_failure()
                self._set_status(f"Entry {current_id} {action}")
            except Exception as exc:
                self._record_failure(
                    "Archive/restore failed",
                    exc,
                    retry=self.action_toggle_archive,
                    hint="Press 'x' to retry.",
                )

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
            self._doc_snapshot = {
                "label": str(entry.get("label", "")),
                "file_type": str(entry.get("file_type", "txt")).lstrip("."),
                "tags": tags_text,
                "content": str(entry.get("content", "")),
            }
            self._doc_dirty = False
            self._set_document_editor_visible(True)
            self._refresh_doc_edit_help()
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
            current_form = {
                "label": label,
                "file_type": file_type,
                "tags": tags_raw,
                "content": content,
            }
            self._doc_dirty = current_form != self._doc_snapshot
            self._refresh_doc_edit_help()
            if not self._doc_dirty:
                self._set_status("No document changes to save")
                return

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
                self._doc_dirty = False
                self._load_entries(self._last_query, reset_page=False)
                if current_id in self._entry_ids_in_view:
                    self._show_entry(current_id)
                self._clear_failure()
                self._set_status(f"Saved document {current_id}")
            except Exception as exc:
                self._record_failure(
                    "Failed to save document",
                    exc,
                    retry=self.action_save_document,
                    hint="Press 'x' to retry.",
                )

        def action_cancel_document_edit(self) -> None:
            if self.palette_open:
                self._set_palette_visible(False)
                self._set_status("Palette closed")
                return
            if self.help_open:
                self.help_open = False
                self._update_help_overlay()
                self._set_status("Help closed")
                return
            if not self.editing_document:
                return
            self._set_document_editor_visible(False)
            self._doc_dirty = False
            self._set_status("Canceled document edit")

        def on_input_changed(self, event: Input.Changed) -> None:
            if event.input.id in {
                "doc-edit-label",
                "doc-edit-file-type",
                "doc-edit-tags",
                "doc-edit-content-single",
            }:
                self._mark_doc_dirty(True)

        def on_text_area_changed(self, _event: Any) -> None:
            self._mark_doc_dirty(True)

        def on_input_submitted(self, event: Input.Submitted) -> None:
            if event.input.id == "search":
                if self.editing_document:
                    self._set_status("Finish document edit before searching")
                    return
                self._load_entries(query=event.value.strip(), reset_page=True)
                return
            if event.input.id == "quick-jump":
                raw = event.value.strip()
                if not raw:
                    self._set_status("Jump requires an entry id")
                    return
                try:
                    entry_id = int(raw)
                except ValueError:
                    self._set_status("Jump requires an integer entry id")
                    return
                self._show_entry(entry_id)
                return
            if event.input.id == "command-palette":
                command = event.value
                self._set_palette_visible(False)
                self._run_palette_command(command)

        def on_list_view_selected(self, event: ListView.Selected) -> None:
            if self.editing_document:
                self._set_status("Finish document edit before selecting another entry")
                return
            self._focus_pane = "center"
            self._apply_focus_style()
            item = event.item
            if isinstance(item, EntryListItem):
                self._show_entry(item.entry_index)

    app = SeedPassTuiV2()
    if callable(app_hook):
        app_hook(app)
        return True
    app.run()
    return True
