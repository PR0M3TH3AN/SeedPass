from __future__ import annotations

import importlib.util
import json
import shlex
import time
from pathlib import Path
from types import SimpleNamespace
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


def render_qr_ascii(data: str) -> str:
    """Render ``data`` as an ASCII QR code."""
    import qrcode

    qr = qrcode.QRCode(border=1)
    qr.add_data(data)
    qr.make(fit=True)
    matrix = qr.get_matrix()
    lines: list[str] = []
    for row in matrix:
        lines.append("".join("##" if cell else "  " for cell in row))
    return "\n".join(lines)


def launch_tui2(
    *,
    fingerprint: str | None = None,
    entry_service_factory: Any | None = None,
    profile_service_factory: Any | None = None,
    config_service_factory: Any | None = None,
    nostr_service_factory: Any | None = None,
    sync_service_factory: Any | None = None,
    utility_service_factory: Any | None = None,
    vault_service_factory: Any | None = None,
    semantic_service_factory: Any | None = None,
    app_hook: Any | None = None,
) -> bool:
    """Launch TUI v2 when runtime dependencies are available.

    Returns ``True`` when launch succeeds, ``False`` when runtime is unavailable.
    """
    runtime = check_tui2_runtime()
    if not runtime["textual_available"]:
        return False

    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Horizontal, Vertical
    from textual.reactive import reactive
    from textual.widgets import Button, Input, Label, ListItem, ListView, Static

    try:
        from textual.widgets import TextArea
    except Exception:  # pragma: no cover - runtime fallback for older textual
        TextArea = None

    from textual.screen import Screen

    class EntryListItem(ListItem):
        def __init__(self, entry_index: int, text: str) -> None:
            super().__init__(Label(text))
            self.entry_index = int(entry_index)

    class SettingsScreen(Screen):
        """Full-screen settings management."""

        BINDINGS = [("escape", "app.pop_screen", "Back")]

        def compose(self) -> ComposeResult:
            yield Static("SeedPass ◈ Settings", id="settings-title")
            with Vertical(id="settings-container"):
                yield Static("", id="settings-content")
            yield Static("Press ESC to return to vault", id="settings-footer")

        def on_mount(self) -> None:
            self._refresh_settings()

        def _refresh_settings(self) -> None:
            # We use app properties via self.app
            app = self.app
            if app._config_service is None:
                self.query_one("#settings-content", Static).update(
                    "Config service unavailable"
                )
                return

            def get_val(key, default=""):
                try:
                    return app._config_service.get(key) or default
                except Exception:
                    return "(error)"

            security_rows = [
                f"Secret Mode    : {get_val('secret_mode_enabled', False)}  (setting-secret on|off)",
                f"Quick Unlock   : {get_val('quick_unlock', False)}  (setting-quick-unlock on|off)",
                f"KDF Iterations : {get_val('kdf_iterations', 100000)}  (setting-kdf-iterations <n>)",
                f"KDF Mode       : {get_val('kdf_mode', 'argon2id')}  (setting-kdf-mode <mode>)",
                f"Lock Timeout   : {get_val('inactivity_timeout', 300)}s  (setting-timeout <s>)",
            ]

            backup_rows = [
                f"Backup Path    : {get_val('additional_backup_path', '(none)')}  (db-export <path>)",
                f"Backup Interval: {get_val('backup_interval', 3600)}s",
            ]

            nostr_rows = [
                f"Sync Mode      : {get_val('semantic_search_mode', 'keyword')}  (search-mode ...)",
                f"Relays         : {len(get_val('relays', []))}  (relay-list)",
            ]

            rendered_lines = [
                *app._board_card("Security Configuration", security_rows),
                "",
                *app._board_card("Storage & Backup", backup_rows),
                "",
                *app._board_card("Connectivity & Nostr", nostr_rows),
            ]
            self.query_one("#settings-content", Static).update(
                "\n".join(rendered_lines)
            )

    class InspectorScreen(Screen):
        """Full-screen maximized entry detail view."""

        BINDINGS = [
            ("escape", "app.pop_screen", "Back"),
            ("v", "reveal", "Reveal"),
            ("g", "qr", "QR"),
        ]

        def compose(self) -> ComposeResult:
            yield Static("SeedPass ◈ Detailed Inspection", id="inspector-title")
            with Vertical(id="inspector-container"):
                yield Static("", id="maximized-detail")
            yield Static("ESC: Back | v: Reveal | g: QR", id="inspector-footer")

        def on_mount(self) -> None:
            self._refresh_detail()

        def _refresh_detail(self) -> None:
            app = self.app
            if app._selected_entry_id is None:
                self.query_one("#maximized-detail", Static).update("No entry selected.")
                return

            # Use app's rendering logic but formatted for full screen
            detail = app._entry_detail_text(app._selected_entry)
            self.query_one("#maximized-detail", Static).update(detail)

        def action_reveal(self) -> None:
            self.app.action_reveal_selected()
            self._refresh_detail()

        def action_qr(self) -> None:
            self.app.action_show_qr()
            self._refresh_detail()

    class SeedPassTuiV2(App[None]):
        RESULT_PAGE_SIZE = 200
        DETAIL_CONTENT_PREVIEW_LIMIT = 4000
        FILTER_PRESETS: dict[str, list[str] | None] = {
            "all": None,
            "secrets": [
                "password",
                "stored_password",
                "seed",
                "managed_account",
                "ssh",
                "pgp",
                "nostr",
                "key_value",
            ],
            "docs": ["document", "note"],
            "keys": ["seed", "managed_account", "ssh", "pgp", "nostr"],
            "2fa": ["totp"],
        }

        CSS = """
        Screen {
            background: #080a0c;
            color: #97b8a6;
        }
        #brand-strip {
            background: #0b0f13;
            color: #58f29d;
            text-style: bold;
            border: solid #2abf75;
            margin: 0 1 0 1;
            padding: 0 1;
            height: 3;
        }
        Input {
            background: #0d1114;
            color: #daf2e5;
            border: solid #1a3024;
        }
        Input:focus {
            border: heavy #58f29d;
        }
        ListView {
            background: #0d1114;
            border: solid #1a3024;
        }
        ListItem {
            color: #97b8a6;
            height: 1;
        }
        ListItem.-highlight {
            background: #122019;
            color: #daf2e5;
            text-style: bold;
        }
        Static {
            color: #97b8a6;
        }
        #command-palette {
            height: 2;
            margin: 0 1 1 1;
            border: solid #2abf75;
            background: #0d1114;
            color: #daf2e5;
        }
        #top-ribbon {
            height: 3;
            padding: 0 1;
            margin: 0 1;
            border: heavy #2abf75;
            background: #10181f;
            color: #daf2e5;
            text-style: bold;
        }
        #body { height: 1fr; margin: 0 1; }
        #top-work { height: 6fr; }
        #status {
            height: 3;
            padding: 0 1;
            border: heavy #58f29d;
            background: #11191f;
            color: #e4fff2;
            margin: 0 1 0 1;
        }
        #action-strip {
            height: 3;
            padding: 0 1;
            margin: 0 1;
            border: heavy #2abf75;
            background: #11191f;
            color: #daf2e5;
        }
        #left { width: 31; border: solid #1a3024; padding: 0 1; background: #0d1114; }
        #left.sidebar-collapsed { width: 3; padding: 0; }
        #sidebar-toggle {
            height: 1;
            min-height: 1;
            margin: 0;
            border: none;
            background: transparent;
            color: #58f29d;
            text-style: bold;
            content-align: left middle;
        }
        #center { width: 1fr; border: solid #1a3024; padding: 0 1; background: #0d1114; margin-left: 1; }
        #right { height: 5fr; border: heavy #3ce79c; padding: 1; background: #0d1114; margin-top: 0; }
        #grid-heading {
            height: 4;
            margin-bottom: 0;
            border: solid #274533;
            background: #0b0f13;
            color: #daf2e5;
            text-style: bold;
            padding: 0 1;
            overflow: hidden;
        }
        #inspector-heading {
            height: 3;
            margin-bottom: 0;
            border: solid #274533;
            background: #0b0f13;
            color: #daf2e5;
            text-style: bold;
            padding: 0 1;
        }
        #inspector-grid { height: 1fr; }
        #inspector-side { width: 28; height: 1fr; margin-left: 1; }
        #filters {
            height: 1fr;
            overflow: auto;
        }
        #search { margin-bottom: 0; }
        #quick-jump { margin-bottom: 0; }
        #kind-filter-input {
            margin-bottom: 0;
            border: solid #2abf75;
        }
        #entry-list { height: 1fr; }
        #entry-detail {
            width: 1fr;
            height: 1fr;
            overflow: auto;
            border: solid #58f29d;
            padding: 0;
        }
        #link-detail {
            min-height: 3;
            height: 2fr;
            overflow: auto;
            border: solid #2abf75;
            padding: 0;
        }
        #secret-detail {
            min-height: 3;
            height: 1fr;
            overflow: auto;
            border: solid #58f29d;
            padding: 0;
            margin-top: 0;
            text-wrap: nowrap;
        }
        #totp-board {
            height: 10;
            overflow: auto;
            border: solid #2abf75;
            padding: 1;
            margin-top: 0;
        }
        #settings-board {
            height: 1fr;
            overflow: auto;
            border: solid #2abf75;
            padding: 1;
            margin-top: 0;
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
            border: solid #58f29d;
            padding: 1;
            background: #0d1114;
            color: #daf2e5;
        }
        #activity {
            height: 3;
            border: solid #274533;
            padding: 1;
            margin-top: 0;
            overflow: auto;
        }
        .pane-focus { border: heavy #58f29d; }
        .hidden { display: none; }

        #settings-title, #inspector-title {
            background: #0b0f13;
            color: #58f29d;
            text-style: bold;
            text-align: center;
            height: 3;
            border: double #2abf75;
            padding: 0 1;
        }
        #settings-container, #inspector-container {
            height: 1fr;
            margin: 1 2;
            border: solid #1a3024;
            padding: 1;
            overflow: auto;
        }
        #settings-footer, #inspector-footer {
            height: 3;
            background: #11191f;
            color: #daf2e5;
            text-align: center;
            border: double #2abf75;
            padding: 0 1;
        }
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
            ("f", "toggle_filter_menu", "Filter Menu"),
            ("shift+f", "cycle_filter", "Filter"),
            ("m", "cycle_search_mode", "Search Mode"),
            ("d", "toggle_density", "Density"),
            ("shift+s", "shortcut_settings", "Settings"),
            ("shift+a", "shortcut_add_entry", "Add Entry"),
            ("shift+c", "shortcut_create_seed", "Create Seed"),
            ("shift+r", "shortcut_remove_seed", "Remove Seed"),
            ("shift+h", "shortcut_hide_reveal", "Hide/Reveal"),
            ("shift+e", "shortcut_export_data", "Export Data"),
            ("shift+i", "shortcut_import_data", "Import Data"),
            ("shift+b", "shortcut_backup_data", "Backup Data"),
            ("h", "cycle_archive_scope", "Archive View"),
            ("up", "profile_tree_prev", "Profile Prev"),
            ("down", "profile_tree_next", "Profile Next"),
            ("ctrl+o", "profile_tree_open", "Profile Open"),
            ("u", "profile_tree_preview", "Profile Preview"),
            ("space", "profile_tree_toggle", "Toggle Node"),
            ("right", "profile_tree_toggle", "Expand"),
            ("p", "prev_page", "Prev Page"),
            ("n", "next_page", "Next Page"),
            ("l", "cycle_link_filter", "Link Filter"),
            ("[", "prev_link", "Prev Link"),
            ("]", "next_link", "Next Link"),
            ("o", "open_link_target", "Open Link"),
            Binding("v", "reveal_selected", "Reveal", priority=True),
            Binding("g", "show_qr", "QR", priority=True),
            ("6", "toggle_totp_board", "2FA Board"),
            ("a", "toggle_archive", "Archive/Restore"),
            ("e", "edit_document", "Edit Document"),
            ("ctrl+s", "save_document", "Save"),
            ("ctrl+p", "open_palette", "Palette"),
            ("ctrl+b", "toggle_sidebar", "Sidebar"),
            ("escape", "cancel_document_edit", "Cancel"),
            ("z", "maximize_inspector", "Maximize"),
        ]

        filter_kind: reactive[str] = reactive("all")
        archive_scope: reactive[str] = reactive("active")
        link_relation_filter: reactive[str] = reactive("all")
        editing_document: reactive[bool] = reactive(False)
        palette_open: reactive[bool] = reactive(False)
        help_open: reactive[bool] = reactive(False)
        totp_board_open: reactive[bool] = reactive(False)
        settings_open: reactive[bool] = reactive(False)

        def compose(self) -> ComposeResult:
            yield Input(
                placeholder=(
                    "Command palette: help | open <id> | search <q> | "
                    "help-commands | onboarding | quickstart | stats | session-status | lock | unlock <password> | "
                    "density <compact|comfortable> | "
                    "filter <kind|comma-list|all|secrets|docs|keys|2fa> | archive | restore | "
                    "archive-filter <active|all|archived> | "
                    "add-password <label> <length> [username] [url] | "
                    "add-totp <label> [period] [digits] [secret] | "
                    "add-key-value <label> <key> <value> | "
                    "add-document <label> <file_type> <content> | "
                    "add-ssh <label> [index] | add-pgp <label> [index] [key_type] [user_id] | "
                    "add-nostr <label> [index] | add-seed <label> [words] [index] | "
                    "add-managed-account <label> [index] | "
                    "notes-set <text> | notes-clear | tag-add <tag> | tag-rm <tag> | "
                    "tags-set <comma-list> | tags-clear | field-add <label> <value> [hidden] | "
                    "field-rm <label> | set-field <name> <value> | clear-field <name> | "
                    "2fa-board | 2fa-hide | 2fa-refresh | 2fa-copy <entry_id> | 2fa-copy-url <entry_id> | "
                    "profiles-list | profile-switch <fp> [password] | profile-add | "
                    "profile-remove <fp> | profile-rename <fp> <name> | "
                    "profile-tree-next | profile-tree-prev | profile-tree-open | "
                    "setting-secret <on|off> [delay] | setting-offline <on|off> | "
                    "setting-quick-unlock <on|off> | setting-timeout <seconds> | "
                    "setting-kdf-iterations <n> | setting-kdf-mode <mode> | "
                    "search-mode <keyword|hybrid|semantic> | semantic-status | semantic-enable | semantic-disable | semantic-build | semantic-rebuild | semantic-search <query> | "
                    "relay-list | relay-add <url> | relay-rm <index> | "
                    "relay-reset | npub | nostr-reset-sync-state | nostr-fresh-namespace | "
                    "sync-now | sync-bg | "
                    "checksum-verify | checksum-update | db-export <path> | db-import <path> | "
                    "totp-export <path> | parent-seed-backup [path] [password] | "
                    "managed-load [entry_id] | managed-exit | session-status | lock | unlock <password> | "
                    "doc-export [output_path] | "
                    "copy <field> [confirm] | "
                    "export-field <field> <path> [confirm] | "
                    "link-add <target> [relation] [note] | "
                    "link-rm <target> [relation] | "
                    "reveal [confirm] | qr [public|private] [confirm] | "
                    "link-filter <relation|all> | link-next | link-prev | link-open | "
                    "page-next | page-prev | page <n> | retry"
                ),
                id="command-palette",
                classes="hidden",
            )
            yield Static("", id="help-overlay", classes="hidden")
            yield Static("SeedPass ◈ UI v2", id="brand-strip")
            yield Static("", id="top-ribbon")
            with Vertical(id="body"):
                with Horizontal(id="top-work"):
                    with Vertical(id="left"):
                        yield Button("◀ Collapse", id="sidebar-toggle")
                        yield Static("", id="filters")
                        yield Static("", id="activity")
                    with Vertical(id="center"):
                        yield Static("", id="grid-heading")
                        yield Input(
                            placeholder="Search entries (Enter to apply)", id="search"
                        )
                        yield Input(
                            placeholder="Jump to entry id (Enter)", id="quick-jump"
                        )
                        yield Input(
                            placeholder="Filter presets: all | secrets | docs | keys | 2fa (Enter)",
                            id="kind-filter-input",
                            classes="hidden",
                        )
                        yield ListView(id="entry-list")
                with Vertical(id="right"):
                    with Vertical(id="right-view"):
                        yield Static("Inspector Board", id="inspector-heading")
                        with Horizontal(id="inspector-grid"):
                            yield Static("", id="entry-detail")
                            with Vertical(id="inspector-side"):
                                yield Static("", id="link-detail")
                                yield Static("", id="secret-detail")
                        yield Static("", id="totp-board", classes="hidden")
                        yield Static("", id="settings-board", classes="hidden")
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
            yield Static("", id="action-strip")

        def on_mount(self) -> None:
            self._service = None
            self._profile_service = None
            self._config_service = None
            self._nostr_service = None
            self._sync_service = None
            self._utility_service = None
            self._vault_service = None
            self._semantic_service = None
            self._semantic_state = "n/a"
            self._semantic_mode = "keyword"
            self._selected_entry_id: int | None = None
            self._selected_entry: dict[str, Any] | None = None
            self._last_query = ""
            self._entry_ids_in_view: list[int] = []
            self._all_results: list[tuple[Any, ...]] = []
            self._result_page = 0
            self._current_links: list[dict[str, Any]] = []
            self._current_link_cursor = 0
            self._search_reason_by_id: dict[int, str] = {}
            self._last_error: str | None = None
            self._retry_action: Any | None = None
            self._activity_log: list[str] = []
            self._focus_pane = "center"
            self._doc_dirty = False
            self._doc_snapshot: dict[str, Any] = {}
            self._last_status_message = ""
            self._time_now = time.time
            self._totp_rows: list[dict[str, Any]] = []
            self._session_locked = False
            self._managed_session_entry_id: int | None = None
            self._managed_session_stack: list[dict[str, Any]] = []
            self._last_sync_text = "(none)"
            self._density_mode = "compact"
            self._profile_tree_items: list[str] = []
            self._profile_tree_cursor = 0
            self._profile_tree_expanded: dict[str, bool] = {}
            self._compact_layout = False
            self._dense_hires_layout = False
            self._viewport_width = 0
            self._viewport_height = 0
            self._pending_sensitive_confirm: tuple[str, int, float] | None = None
            self._sidebar_collapsed = False
            self._active_profile_fp = (fingerprint or "").strip()
            self._root_profile_fp = self._active_profile_key()
            self._profile_filter_by_fp: dict[str, str] = {}
            self._profile_sidebar_by_fp: dict[str, bool] = {}
            self._totp_tick = self.set_interval(1.0, self._tick_totp_board)
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
            try:
                self._profile_service = (
                    profile_service_factory()
                    if callable(profile_service_factory)
                    else None
                )
            except Exception as exc:
                self._profile_service = None
                self._log_activity(f"Profile service unavailable: {exc}")
            try:
                self._config_service = (
                    config_service_factory()
                    if callable(config_service_factory)
                    else None
                )
            except Exception as exc:
                self._config_service = None
                self._log_activity(f"Config service unavailable: {exc}")
            try:
                self._nostr_service = (
                    nostr_service_factory() if callable(nostr_service_factory) else None
                )
            except Exception as exc:
                self._nostr_service = None
                self._log_activity(f"Nostr service unavailable: {exc}")
            try:
                self._sync_service = (
                    sync_service_factory() if callable(sync_service_factory) else None
                )
            except Exception as exc:
                self._sync_service = None
                self._log_activity(f"Sync service unavailable: {exc}")
            try:
                self._utility_service = (
                    utility_service_factory()
                    if callable(utility_service_factory)
                    else None
                )
            except Exception as exc:
                self._utility_service = None
                self._log_activity(f"Utility service unavailable: {exc}")
            try:
                self._vault_service = (
                    vault_service_factory() if callable(vault_service_factory) else None
                )
            except Exception as exc:
                self._vault_service = None
                self._log_activity(f"Vault service unavailable: {exc}")
            try:
                self._semantic_service = (
                    semantic_service_factory()
                    if callable(semantic_service_factory)
                    else None
                )
            except Exception as exc:
                self._semantic_service = None
                self._log_activity(f"Semantic service unavailable: {exc}")
            self._refresh_semantic_state()
            self._update_filters_panel()
            self._update_help_overlay()
            self._update_activity_panel()
            self._apply_focus_style()
            self._refresh_profile_tree()
            self._restore_filter_for_active_profile(default_filter="all")
            self._update_top_ribbon()
            self._update_action_strip()
            self._set_secret_panel(
                "Sensitive data hidden. Use 'v' to reveal 🔑 or 'g' for QR ▦."
            )
            self._update_inspector_heading()
            self._update_responsive_layout()
            self._load_entries()
            # Keep primary navigation on the entry list so global action keys
            # (v/g/a/e) work immediately after launch.
            self.query_one("#entry-list", ListView).focus()

        def _set_status(self, message: str) -> None:
            if message == self._last_status_message:
                return
            self._last_status_message = message
            mode = (
                "PALETTE"
                if self.palette_open
                else ("EDIT" if self.editing_document else "VIEW")
            )
            text = (
                f"[{mode} | {self._focus_pane.upper()}] "
                "Shortcuts: ? help  Ctrl+P cmd  / search\n"
                f"{message}"
            )
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

        def _set_secret_panel(self, text: str, *, state: str | None = "HIDDEN") -> None:
            if state:
                rendered = f"Sensitive State: {state}\n\n{text}"
            else:
                rendered = text
            self.query_one("#secret-detail", Static).update(rendered)

        def _select_highlighted_entry_for_sensitive_action(self) -> bool:
            if self._selected_entry_id is not None:
                return True
            list_view = self.query_one("#entry-list", ListView)
            item = getattr(list_view, "highlighted_child", None)
            if isinstance(item, EntryListItem):
                self._show_entry(item.entry_index)
            return self._selected_entry_id is not None

        def _update_top_ribbon(self) -> None:
            lock_state = "locked" if self._session_locked else "unlocked"
            managed_rows, _agent_rows = self._profile_tree_child_nodes()
            managed = str(len(managed_rows))
            total = len(self._all_results)
            pw_count = 0
            twofa_count = 0
            doc_count = 0
            key_count = 0
            for row in self._all_results:
                if len(row) < 6:
                    continue
                kind_obj = row[5]
                kind = str(getattr(kind_obj, "value", kind_obj)).strip().lower()
                if kind in {"password", "stored_password"}:
                    pw_count += 1
                elif kind == "totp":
                    twofa_count += 1
                elif kind in {"document", "note"}:
                    doc_count += 1
                elif kind in {
                    "seed",
                    "managed_account",
                    "ssh",
                    "pgp",
                    "nostr",
                    "key_value",
                }:
                    key_count += 1
            fp_text = self._active_profile_key()
            if len(fp_text) > 16:
                fp_text = f"{fp_text[:13]}..."
            sync_text = self._last_sync_text or "(none)"
            if len(sync_text) > 26:
                sync_text = f"{sync_text[:23]}..."
            text = (
                f"FP {fp_text}"
                f" | Managed Users: {managed}"
                f" | Entries: {total}"
                f" | PW:{pw_count} 2FA:{twofa_count} DOC:{doc_count} KEY:{key_count}"
                f" | Kind: {self.filter_kind}"
                f" | Session: {lock_state}"
                f" | Last Sync: {sync_text}"
            )
            self.query_one("#top-ribbon", Static).update(text)

        def _refresh_semantic_state(self) -> None:
            if self._semantic_service is None:
                self._semantic_state = "n/a"
                return
            status = getattr(self._semantic_service, "status", None)
            if not callable(status):
                self._semantic_state = "n/a"
                return
            try:
                payload = status() or {}
                enabled = bool(payload.get("enabled", False))
                built = bool(payload.get("built", False))
                records = int(payload.get("records", 0))
                mode = str(payload.get("mode", "keyword")).strip().lower()
                self._semantic_mode = (
                    mode if mode in {"keyword", "hybrid", "semantic"} else "keyword"
                )
                if not enabled:
                    self._semantic_state = "off"
                elif built:
                    self._semantic_state = f"ready({records})"
                else:
                    self._semantic_state = "stale"
            except Exception:
                self._semantic_state = "err"

        def _refresh_profile_tree(self) -> None:
            profiles: list[str] = []
            if self._profile_service is not None:
                lister = getattr(self._profile_service, "list_profiles", None)
                if callable(lister):
                    try:
                        profiles = [str(item) for item in lister() if str(item).strip()]
                    except Exception:
                        profiles = []
            if not profiles:
                profiles = [self._active_profile_key()]
            self._profile_tree_items = profiles
            self._profile_tree_cursor = max(0, self._profile_tree_cursor)

        def _profile_tree_child_nodes(
            self,
        ) -> tuple[list[tuple[int, str]], list[tuple[int, str]]]:
            managed: list[tuple[int, str]] = []
            agent_like: list[tuple[int, str]] = []
            source_rows: list[tuple[Any, ...]] = []
            if self._service is not None and self._all_results:
                try:
                    source_rows = list(
                        self._service.search_entries(
                            "",
                            kinds=["managed_account", "nostr"],
                            include_archived=False,
                            archived_only=False,
                        )
                    )
                except Exception:
                    source_rows = []
            if not source_rows:
                source_rows = list(self._all_results)
            for row in source_rows:
                if len(row) < 6:
                    continue
                entry_id = int(row[0])
                label = str(row[1] or f"entry-{entry_id}").strip()
                kind_obj = row[5]
                kind = str(getattr(kind_obj, "value", kind_obj)).strip().lower()
                if kind == "managed_account" and len(managed) < 6:
                    managed.append((entry_id, label))
                elif kind == "nostr" and len(agent_like) < 6:
                    agent_like.append((entry_id, label))
            return managed, agent_like

        def _profile_tree_visible_nodes(self) -> list[dict[str, Any]]:
            nodes: list[dict[str, Any]] = []
            profiles = list(self._profile_tree_items[:6])
            current_fp = self._active_profile_key()
            if current_fp == "(default)" and "(default)" not in profiles:
                current_fp = ""
            managed_nodes, agent_nodes = self._profile_tree_child_nodes()
            if not profiles:
                profiles = [current_fp or "(default)"]
            for fp in profiles:
                nodes.append({"kind": "profile", "fingerprint": fp})
                # Auto-expand the active profile if not explicitly tracked
                if fp not in self._profile_tree_expanded:
                    self._profile_tree_expanded[fp] = fp == current_fp

                if not self._profile_tree_expanded.get(fp, False):
                    continue

                # Only show child nodes for the ACTIVE profile branch for now
                # (since searching across all profiles is expensive)
                is_active_branch = fp == current_fp or (
                    not current_fp and fp == "(default)"
                )
                if not is_active_branch:
                    continue

                for entry_id, label in managed_nodes[:3]:
                    nodes.append(
                        {
                            "kind": "managed",
                            "entry_id": int(entry_id),
                            "label": str(label),
                        }
                    )
                for entry_id, label in agent_nodes[:3]:
                    nodes.append(
                        {
                            "kind": "agent",
                            "entry_id": int(entry_id),
                            "label": str(label),
                        }
                    )
            return nodes

        @staticmethod
        def _profile_tree_selection_text(node: dict[str, Any]) -> str:
            kind = str(node.get("kind", ""))
            if kind == "profile":
                return f"Profile selection: {str(node.get('fingerprint', ''))}"
            if kind == "managed":
                return (
                    f"Managed selection: #{int(node.get('entry_id', 0))} "
                    f"{str(node.get('label', ''))}"
                )
            if kind == "agent":
                return (
                    f"Agent selection: #{int(node.get('entry_id', 0))} "
                    f"{str(node.get('label', ''))}"
                )
            return "Tree selection updated"

        def _set_sidebar_collapsed(self, collapsed: bool) -> None:
            self._sidebar_collapsed = bool(collapsed)
            self._remember_sidebar_for_active_profile()
            left = self.query_one("#left", Vertical)
            toggle = self.query_one("#sidebar-toggle", Button)
            filters = self.query_one("#filters", Static)
            activity = self.query_one("#activity", Static)
            if self._sidebar_collapsed:
                left.add_class("sidebar-collapsed")
                filters.add_class("hidden")
                activity.add_class("hidden")
                toggle.label = "▶ Expand"
                if self._focus_pane == "left":
                    self._focus_pane = "center"
                    self._apply_focus_style()
            else:
                left.remove_class("sidebar-collapsed")
                filters.remove_class("hidden")
                activity.remove_class("hidden")
                toggle.label = "◀ Collapse"
                if self._viewport_height >= 36 and not self._compact_layout:
                    activity.remove_class("hidden")
            self._update_action_strip()

        def _set_filter_menu_visible(self, visible: bool) -> None:
            filter_input = self.query_one("#kind-filter-input", Input)
            if visible:
                filter_input.remove_class("hidden")
                filter_input.value = ""
                filter_input.focus()
                self._set_status("Filter menu: enter all|secrets|docs|keys|2fa")
            else:
                filter_input.add_class("hidden")
                if self._focus_pane == "center":
                    self.query_one("#entry-list", ListView).focus()

        def _set_inspector_side_visible(self, visible: bool) -> None:
            link_detail = self.query_one("#link-detail", Static)
            secret_detail = self.query_one("#secret-detail", Static)
            if not visible:
                link_detail.add_class("hidden")
                secret_detail.add_class("hidden")
                return
            secret_detail.remove_class("hidden")
            if self._compact_layout:
                link_detail.add_class("hidden")
            else:
                link_detail.remove_class("hidden")

        def _update_action_strip(self) -> None:
            kind_l = ""
            if isinstance(self._selected_entry, dict):
                kind_l = self._entry_kind(self._selected_entry)
            kind = kind_l
            if kind_l in {"password", "stored_password"}:
                context = "Entry ▣ Reveal (v) ▣ QR (g) ▣ Edit (e) ▣ Archive (a) ▣ Maximize (z)"
            elif kind_l == "managed_account":
                context = "Entry ▣ managed-load ▣ managed-exit ▣ Reveal (v confirm) ▣ QR (g) ▣ Edit (e) ▣ Archive (a) ▣ Maximize (z)"
            elif kind_l == "seed":
                context = "Entry ▣ Reveal (v confirm) ▣ QR (g) ▣ Edit (e) ▣ Archive (a) ▣ Maximize (z)"
            elif kind_l == "totp":
                context = "Entry ▣ 2FA Board (6) ▣ Reveal (v) ▣ QR (g) ▣ Archive (a) ▣ Maximize (z)"
            elif kind_l in {"ssh", "pgp"}:
                context = "Entry ▣ Reveal (v confirm) ▣ Archive (a) ▣ copy/export-field ▣ Maximize (z)"
            elif kind_l == "nostr":
                context = "Entry ▣ Reveal (v) ▣ QR (g public/private) ▣ Archive (a) ▣ Maximize (z)"
            elif kind_l in {"document", "note"}:
                context = "Entry ▣ Edit Doc (e) ▣ Save (Ctrl+S) ▣ Archive (a) ▣ Maximize (z) ▣ doc-export"
            elif kind_l == "key_value":
                context = "Entry ▣ set-field/clear-field ▣ Archive (a) ▣ Maximize (z) ▣ notes/tags"
            else:
                context = "Select an entry to view context actions."
            if kind:
                context = f"{context} ({kind_l})"
            if self._compact_layout:
                global_row = "Settings (S)  Add (A)  Seed+ (C)  Seed- (R)  Reveal (H)  Export (E)  Import (I)  Backup (B)  Cmd (Ctrl+P)"
                if self._viewport_width and self._viewport_width < 130:
                    context = context.replace("Entry ▣ ", "")
                    context = context.replace("Reveal", "Rev")
                    context = context.replace("Archive", "Arch")
                    context = context.replace("confirm", "cfm")
            elif self._dense_hires_layout:
                global_row = (
                    "Shift+S Set  Shift+A Add  Shift+C Seed+  Shift+R Seed-  Shift+H Reveal  Shift+E Export  Shift+I Import  "
                    "Shift+B Backup  Ctrl+P Cmd  Dense"
                )
                context = context.replace("Entry ▣ ", "")
                context = context.replace("Reveal", "Rev")
                context = context.replace("Archive", "Arch")
                context = context.replace("confirm", "cfm")
            else:
                global_row = (
                    "Settings (Shift+S)  Add (Shift+A)  Seed+ (Shift+C)  Seed- (Shift+R)  "
                    "Reveal (Shift+H)  Export (Shift+E)  Import (Shift+I)  Backup (B)  Cmd (Ctrl+P)"
                )
            text = f"{global_row}\n{context}"
            self.query_one("#action-strip", Static).update(text)

        def _update_grid_heading(self) -> None:
            modes = ["keyword", "hybrid", "semantic"]
            chips = " ".join(
                [
                    (
                        f"({item.upper()})"
                        if str(self._semantic_mode).strip().lower() == item
                        else item
                    )
                    for item in modes
                ]
            )
            table_cols = (
                "Sel Id       Entry#   Label                       Kind            "
                "Meta                      Arch"
            )
            divider = "-" * len(table_cols)
            metrics = (
                f"Pg {self._result_page + 1}/{self._total_pages()}  "
                f"Rows {len(self._entry_ids_in_view)}/{len(self._all_results)}  "
                f"Density {self._density_mode}  Search {chips}"
            )
            self.query_one("#grid-heading", Static).update(
                "\n".join(
                    [
                        f"Entry Grid  |  {metrics}",
                        table_cols,
                        divider,
                    ]
                )
            )

        @staticmethod
        def _action_strip_segment_action(segment: str) -> str | None:
            token = segment.strip()
            # Be more flexible with shortcut indicators (S), (Shift+S), or "S "
            if "Settings" in token:
                return "settings"
            if "Add" in token:
                return "add"
            if "Seed+" in token:
                return "create_seed"
            if "Seed-" in token:
                return "remove_seed"
            if "Reveal" in token or "Rev" in token:
                return "hide_reveal"
            if "Export" in token:
                return "export"
            if "Import" in token:
                return "import"
            if "Backup" in token:
                return "backup"
            if "Cmd" in token or "Ctrl+P" in token:
                return "palette"
            return None

        @staticmethod
        def _action_strip_context_action(segment: str) -> str | None:
            token = segment.strip()
            if not token:
                return None
            lead = token.split()[0].strip().lower()
            if lead in {"v", "reveal", "rev"}:
                return "reveal"
            if lead in {"g", "qr"}:
                return "qr"
            if lead in {"e", "edit"}:
                return "edit"
            if lead in {"a", "archive", "arch"}:
                return "archive"
            if lead in {"z", "maximize", "max"}:
                return "maximize"
            if lead in {"6", "2fa"}:
                return "totp_board"
            if lead in {"managed-load", "managed_load", "ml"}:
                return "managed_load"
            if lead in {"managed-exit", "managed_exit", "mx"}:
                return "managed_exit"
            return None

        def _trigger_action_strip_shortcut(self, action: str) -> None:
            if action == "settings":
                self.action_shortcut_settings()
            elif action == "add":
                self.action_shortcut_add_entry()
            elif action == "create_seed":
                self.action_shortcut_create_seed()
            elif action == "remove_seed":
                self.action_shortcut_remove_seed()
            elif action == "hide_reveal":
                self.action_shortcut_hide_reveal()
            elif action == "export":
                self.action_shortcut_export_data()
            elif action == "import":
                self.action_shortcut_import_data()
            elif action == "backup":
                self.action_shortcut_backup_data()
            elif action == "palette":
                self.action_open_palette()

        def _trigger_action_strip_context(self, action: str) -> None:
            if action == "reveal":
                self.action_reveal_selected()
            elif action == "qr":
                self.action_show_qr()
            elif action == "edit":
                self.action_edit_document()
            elif action == "archive":
                self.action_toggle_archive()
            elif action == "maximize":
                self.action_maximize_inspector()
            elif action == "totp_board":
                self.action_toggle_totp_board()
            elif action == "managed_load":
                self._run_palette_command("managed-load")
            elif action == "managed_exit":
                self._run_palette_command("managed-exit")

        def _refresh_settings_board(self) -> None:
            if self._config_service is None:
                self.query_one("#settings-board", Static).update(
                    "Config service unavailable"
                )
                return

            def get_val(key, default=""):
                try:
                    return self._config_service.get(key) or default
                except Exception:
                    return "(error)"

            security_rows = [
                f"Secret Mode: {get_val('secret_mode_enabled', False)} (setting-secret on|off)",
                f"Quick Unlock: {get_val('quick_unlock', False)} (setting-quick-unlock on|off)",
                f"KDF Iter: {get_val('kdf_iterations', 100000)} (setting-kdf-iterations <n>)",
                f"KDF Mode: {get_val('kdf_mode', 'argon2id')} (setting-kdf-mode <mode>)",
                f"Lock Timeout: {get_val('inactivity_timeout', 300)}s (setting-timeout <s>)",
            ]

            backup_rows = [
                f"Backup Path: {get_val('additional_backup_path', '(none)')} (db-export <path>)",
                f"Backup Interval: {get_val('backup_interval', 3600)}s",
            ]

            nostr_rows = [
                f"Sync Mode: {get_val('semantic_search_mode', 'keyword')} (search-mode ...)",
                f"Relays: {len(get_val('relays', []))} (relay-list)",
            ]

            rendered_lines = [
                *self._board_card("Security Settings", security_rows),
                "",
                *self._board_card("Backup & Data", backup_rows),
                "",
                *self._board_card("Nostr & Sync", nostr_rows),
            ]
            self.query_one("#settings-board", Static).update("\n".join(rendered_lines))

        def _handle_action_strip_click(self, column: int, row: int) -> bool:
            # This handler receives zero-based coordinates.
            adj_row = row
            adj_col = column
            if adj_row not in {0, 1} or adj_col < 0:
                return False

            rendered = str(self.query_one("#action-strip", Static).render())
            lines = rendered.splitlines()
            if not lines or adj_row >= len(lines):
                return False

            active_line = lines[adj_row]
            if not active_line:
                return False

            import re

            if adj_row == 0:
                segments = list(re.finditer(r"\S+.*?(?=\s{2,}|$)", active_line))
            else:
                segments = list(re.finditer(r"[^▣]+", active_line))

            for match in segments:
                start, end = match.span()
                if start <= adj_col < end:
                    segment_text = match.group(0).strip()
                    action = (
                        self._action_strip_segment_action(segment_text)
                        if adj_row == 0
                        else self._action_strip_context_action(segment_text)
                    )
                    if action:
                        if adj_row == 0:
                            self._trigger_action_strip_shortcut(action)
                        else:
                            self._trigger_action_strip_context(action)
                        return True
            return False

        def _update_inspector_heading(self) -> None:
            heading = "Inspector Board"
            if self.editing_document and self._selected_entry_id is not None:
                heading = f"Document Editor  |  Entry #{self._selected_entry_id}"
            elif self.totp_board_open:
                heading = "2FA Board  |  Live Codes"
            elif self.settings_open:
                heading = "Settings Board  |  Configuration"
            elif (
                isinstance(self._selected_entry, dict)
                and self._selected_entry_id is not None
            ):
                kind = self._entry_kind(self._selected_entry) or "unknown"
                label = str(self._selected_entry.get("label", "")).strip()
                suffix = f"  {label}" if label else ""
                heading = f"Inspector  |  #{self._selected_entry_id} ({kind}){suffix}"
            self.query_one("#inspector-heading", Static).update(heading)

        def _quickstart_text(self) -> str:
            return self._onboarding_text()

        def _onboarding_text(self) -> str:
            return "\n".join(
                [
                    "Onboarding Quick Start",
                    "----------------------",
                    "",
                    "Welcome to SeedPass TUI v2.",
                    "Your vault currently has no active entries.",
                    "",
                    "Step 1: Create your first entry (Ctrl+P then run one command):",
                    '- add-password "Site" 16 user https://site.example  (login)',
                    '- add-totp "Authenticator" 30 6                     (2FA)',
                    '- add-document "Runbook" md "starter notes"         (KB)',
                    "",
                    "Step 2: Inspect and verify",
                    "- open <id> to inspect an entry",
                    "- v to reveal a selected secret, g to render QR when supported",
                    "",
                    "Step 3: Operate and scale",
                    "- stats for vault overview",
                    "- help-commands for full command reference",
                    "- link-add / tag-add / notes-set to build knowledge graph context",
                    "",
                    "Useful navigation:",
                    "- / search, j jump, f filter presets, Shift+F kind cycle, h archive scope",
                    "- 1/2/3 focus panes, ? keyboard help",
                ]
            )

        def _palette_help_summary(self) -> str:
            return (
                "Palette commands: help, help-commands, open, search, filter, "
                "onboarding, quickstart, stats, session-status, lock/unlock, "
                "density, profile-tree-next/prev/open, "
                "search-mode, semantic-status/build/rebuild/search, "
                "archive, restore, archive-filter, edit-doc/save-doc/cancel-edit, "
                "link-add/link-rm/link-filter/link-next/link-prev/link-open, "
                "add-*, notes/tags/fields, 2fa-*, profile-*, setting-*, relay-*, "
                "npub, nostr-reset-sync-state, nostr-fresh-namespace, sync-now/sync-bg, "
                "checksum-*, db-*, totp-export, parent-seed-backup, managed-load/exit, "
                "reveal/qr/copy/export-field, page-*, retry, jump."
            )

        def _palette_reference_text(self) -> str:
            return "\n".join(
                [
                    "Palette Reference",
                    "-----------------",
                    "",
                    "Core: help | help-commands | open <id> | jump <id> | search <q>",
                    "Core Ops: onboarding | quickstart | stats | session-status | lock | unlock <password> | density <compact|comfortable>",
                    "Filters: filter <kind|all> | archive-filter <active|all|archived>",
                    "Pages: page-next | page-prev | page <n>",
                    "",
                    "Entry Actions: archive | restore | reveal [confirm] | qr [public|private] [confirm]",
                    "Docs: edit-doc | save-doc | cancel-edit | doc-export [output_path] | copy <field> [confirm] | export-field <field> <path> [confirm]",
                    "Graph: link-add <target> [relation] [note] | link-rm <target> [relation]",
                    "Graph Nav: link-filter <relation|all> | link-next | link-prev | link-open",
                    "",
                    "Add: add-password | add-totp | add-key-value | add-document | add-ssh | add-pgp | add-nostr | add-seed | add-managed-account",
                    "Entry Fields: notes-set | notes-clear | tag-add | tag-rm | tags-set | tags-clear | field-add | field-rm | set-field | clear-field",
                    "",
                    "2FA: 2fa-board | 2fa-hide | 2fa-refresh | 2fa-copy <entry_id> | 2fa-copy-url <entry_id>",
                    "Profiles: profiles-list | profile-switch | profile-add | profile-remove | profile-rename | profile-tree-next | profile-tree-prev | profile-tree-open",
                    "Settings: setting-secret | setting-offline | setting-quick-unlock | setting-timeout | setting-kdf-iterations | setting-kdf-mode",
                    "Semantic: search-mode <keyword|hybrid|semantic> | semantic-status | semantic-enable | semantic-disable | semantic-build | semantic-rebuild | semantic-search <query>",
                    "Nostr: relay-list | relay-add | relay-rm | relay-reset | npub | nostr-reset-sync-state | nostr-fresh-namespace",
                    "Sync/Utility: sync-now | sync-bg | checksum-verify | checksum-update | db-export | db-import | totp-export | parent-seed-backup",
                    "Sessions: managed-load [entry_id] | managed-exit | session-status | lock | unlock <password>",
                    "",
                    "Tip: use '?' for compact keyboard help overlay.",
                ]
            )

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
                    "Core      : / search   j jump-id   p/n page   f filter menu   Shift+F kind cycle   h archive scope   r refresh",
                    "Search    : m cycle search mode (keyword/hybrid/semantic)",
                    "Modes     : Ctrl+P palette   e edit-doc   Ctrl+S save   Esc cancel/close",
                    "Graph ⚯   : l relation filter   brackets link select   o open link target",
                    "Secrets 🔑: v reveal selected secret   g QR for selected entry",
                    "Resilience: x retry last error",
                    "Pane Focus: 1 left   2 center   3 right",
                    "",
                    "Palette examples",
                    (
                        'help | 2fa-board | 2fa-copy 12 | 2fa-copy-url 12 | add-password "Site" 20 '
                        "user https://x | profiles-list | checksum-verify | db-export backup.enc"
                    ),
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

        def _update_responsive_layout(
            self, width: int | None = None, height: int | None = None
        ) -> None:
            if width is None:
                width = int(getattr(self.size, "width", 0) or 0)
            if height is None:
                height = int(getattr(self.size, "height", 0) or 0)
            self._viewport_width = width
            self._viewport_height = height
            compact = width > 0 and width < 150
            dense_hires = width >= 200 and height >= 50
            previous = bool(getattr(self, "_compact_layout", False))
            previous_dense = bool(getattr(self, "_dense_hires_layout", False))
            try:
                link_detail = self.query_one("#link-detail", Static)
            except Exception:
                self._compact_layout = compact
                self._dense_hires_layout = dense_hires
                return
            if getattr(self, "_selected_entry_id", None) is None:
                link_detail.add_class("hidden")
            elif compact:
                link_detail.add_class("hidden")
            else:
                link_detail.remove_class("hidden")
            try:
                top_work = self.query_one("#top-work", Horizontal)
                right = self.query_one("#right", Vertical)
                activity = self.query_one("#activity", Static)
                brand = self.query_one("#brand-strip", Static)
                ribbon = self.query_one("#top-ribbon", Static)
                status = self.query_one("#status", Static)
                action_strip = self.query_one("#action-strip", Static)
                grid_heading = self.query_one("#grid-heading", Static)
                inspector_heading = self.query_one("#inspector-heading", Static)
                if height > 0 and height < 32:
                    top_work.styles.height = "6fr"
                    right.styles.height = "5fr"
                    activity.add_class("hidden")
                elif height >= 52:
                    if dense_hires and (
                        self._selected_entry_id is None
                        and not self.editing_document
                        and not self.totp_board_open
                    ):
                        # In dense high-res idle state, bias vertical space to the grid.
                        top_work.styles.height = "9fr"
                        right.styles.height = "3fr"
                    else:
                        top_work.styles.height = "8fr"
                        right.styles.height = "4fr"
                    activity.remove_class("hidden")
                    activity.styles.height = 4
                else:
                    if dense_hires and (
                        self._selected_entry_id is None
                        and not self.editing_document
                        and not self.totp_board_open
                    ):
                        top_work.styles.height = "8fr"
                        right.styles.height = "3fr"
                    else:
                        top_work.styles.height = "7fr"
                        right.styles.height = "4fr"
                    activity.remove_class("hidden")
                    activity.styles.height = 3

                # Dense high-resolution mode optimized for larger laptop/desktop
                # viewports (e.g. 2256x1504) to increase content fit.
                if dense_hires:
                    brand.styles.height = 1
                    ribbon.styles.height = 2
                    status.styles.height = 2
                    action_strip.styles.height = 2
                    grid_heading.styles.height = 4
                    inspector_heading.styles.height = 2
                else:
                    brand.styles.height = 3
                    ribbon.styles.height = 3
                    status.styles.height = 3
                    action_strip.styles.height = 3
                    grid_heading.styles.height = 4
                    inspector_heading.styles.height = 3
            except Exception:
                pass
            self._dense_hires_layout = dense_hires
            if compact != previous or dense_hires != previous_dense:
                self._compact_layout = compact
                try:
                    self._update_filters_panel()
                    self._update_action_strip()
                except Exception:
                    pass

        def _refresh_layout_balance(self) -> None:
            self._update_responsive_layout(
                width=self._viewport_width, height=self._viewport_height
            )

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
            token = self._normalize_filter_kind(self.filter_kind)
            if token in self.FILTER_PRESETS:
                return self.FILTER_PRESETS[token]
            if "," in token:
                return [part for part in token.split(",") if part]
            return [token]

        def _active_profile_key(self) -> str:
            fp = str(getattr(self, "_active_profile_fp", "") or "").strip()
            return fp if fp else "(default)"

        @staticmethod
        def _normalize_kind_token(value: Any) -> str:
            token = str(value or "").strip().lower()
            return token.replace("-", "_").replace(" ", "_")

        def _session_fingerprint_path(self) -> list[str]:
            root = str(getattr(self, "_root_profile_fp", "") or "").strip()
            if not root:
                root = self._active_profile_key()
            path = [root]
            for node in self._managed_session_stack:
                fp = str(node.get("fingerprint") or "").strip()
                if not fp:
                    entry_id = int(node.get("entry_id", 0) or 0)
                    fp = f"managed#{entry_id}" if entry_id > 0 else "managed"
                path.append(fp)
            return path

        def _current_fingerprint_display(self) -> str:
            path = self._session_fingerprint_path()
            return path[-1] if path else self._active_profile_key()

        def _session_breadcrumb_text(self) -> str:
            return " > ".join(self._session_fingerprint_path())

        def _remember_filter_for_active_profile(self) -> None:
            key = self._active_profile_key()
            self._profile_filter_by_fp[key] = self._normalize_filter_kind(
                self.filter_kind
            )

        def _restore_filter_for_active_profile(
            self, *, default_filter: str = "all"
        ) -> None:
            key = self._active_profile_key()
            raw = self._profile_filter_by_fp.get(key, default_filter)
            self.filter_kind = self._normalize_filter_kind(raw)

        def _remember_sidebar_for_active_profile(self) -> None:
            key = self._active_profile_key()
            self._profile_sidebar_by_fp[key] = bool(self._sidebar_collapsed)

        def _restore_sidebar_for_active_profile(
            self, *, default_collapsed: bool = False
        ) -> None:
            key = self._active_profile_key()
            collapsed = bool(self._profile_sidebar_by_fp.get(key, default_collapsed))
            self._set_sidebar_collapsed(collapsed)

        def _normalize_filter_kind(self, value: str) -> str:
            token = (value or "all").strip().lower()
            if token in self.FILTER_PRESETS:
                return token
            allowed = {
                "password",
                "stored_password",
                "totp",
                "document",
                "note",
                "key_value",
                "ssh",
                "pgp",
                "nostr",
                "seed",
                "managed_account",
            }
            if "," in token:
                parts: list[str] = []
                seen: set[str] = set()
                for raw in token.split(","):
                    item = raw.strip()
                    if item in allowed and item not in seen:
                        parts.append(item)
                        seen.add(item)
                if parts:
                    return ",".join(parts)
                return "all"
            if token in allowed:
                return token
            return "all"

        def _current_archive_scope_flags(self) -> tuple[bool, bool]:
            if self.archive_scope == "all":
                return True, False
            if self.archive_scope == "archived":
                return True, True
            return False, False

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
            self._refresh_profile_tree()
            tree_lines = (
                ["Tree", "----"]
                if self._dense_hires_layout
                else ["Profile Tree", "------------"]
            )
            current_fp = self._active_profile_key()
            nodes = self._profile_tree_visible_nodes()
            if nodes:
                self._profile_tree_cursor = min(
                    max(0, self._profile_tree_cursor), len(nodes) - 1
                )
                rendered_managed_header = False
                rendered_agent_header = False
                for idx, node in enumerate(nodes):
                    cursor = "▶" if idx == self._profile_tree_cursor else " "
                    kind = str(node.get("kind", ""))
                    if kind == "profile":
                        rendered_managed_header = False
                        rendered_agent_header = False
                        item = str(node.get("fingerprint", ""))
                        marker = "■" if item == current_fp else "□"
                        label = item if item != "(default)" else "default"
                        fp_short = item if len(item) <= 12 else f"{item[:9]}..."
                        active_branch = item == current_fp

                        # Add expand/collapse indicator
                        expanded = self._profile_tree_expanded.get(item, False)
                        exp_ind = "[-] " if expanded else "[+] "

                        branch_suffix = ""
                        if active_branch:
                            managed_count = len(
                                [n for n in nodes if str(n.get("kind")) == "managed"]
                            )
                            agent_count = len(
                                [n for n in nodes if str(n.get("kind")) == "agent"]
                            )
                            branch_suffix = f"  M:{managed_count} A:{agent_count}"

                        tree_lines.append(
                            f"{cursor} {marker} {exp_ind}{label[:12]:<12} | Seed: {fp_short}{branch_suffix}"
                        )
                    elif kind == "managed":
                        if not rendered_managed_header:
                            managed_count = len(
                                [n for n in nodes if str(n.get("kind")) == "managed"]
                            )
                            if self._dense_hires_layout:
                                tree_lines.append(f"    👤 Managed ({managed_count})")
                            else:
                                tree_lines.append(
                                    f"    ├─ 👤 Managed Users ({managed_count})"
                                )
                            rendered_managed_header = True
                        entry_id = int(node.get("entry_id", 0))
                        label = str(node.get("label", ""))[:20]
                        if self._dense_hires_layout:
                            tree_lines.append(f"{cursor}     #{entry_id:<4} {label}")
                        else:
                            tree_lines.append(
                                f"{cursor}    │  └─ #{entry_id:<4} {label}"
                            )
                    elif kind == "agent":
                        if not rendered_agent_header:
                            agent_count = len(
                                [n for n in nodes if str(n.get("kind")) == "agent"]
                            )
                            if self._dense_hires_layout:
                                tree_lines.append(f"    🤖 Agents ({agent_count})")
                            else:
                                tree_lines.append(f"    └─ 🤖 Agents ({agent_count})")
                            rendered_agent_header = True
                        entry_id = int(node.get("entry_id", 0))
                        label = str(node.get("label", ""))[:20]
                        if self._dense_hires_layout:
                            tree_lines.append(f"{cursor}     #{entry_id:<4} {label}")
                        else:
                            tree_lines.append(
                                f"{cursor}       └─ #{entry_id:<4} {label}"
                            )
            else:
                tree_lines.append("▶ ■ default           | Seed: (default)")

            current_fp = self._current_fingerprint_display()
            fp_line = (
                f"Fingerprint: {current_fp}"
                if current_fp != "(default)"
                else "Fingerprint: (default)"
            )
            session_state = "locked" if self._session_locked else "unlocked"
            managed_state = (
                f"#{self._managed_session_entry_id}"
                if self._managed_session_entry_id is not None
                else "(none)"
            )
            profiles_loaded = (
                len(self._profile_tree_items) if self._profile_tree_items else 1
            )
            if self._dense_hires_layout:
                nav_line = "Keys: / j f Shift+F m h p/n ? r x  Pane:1/2/3  Tree:↑/↓ Ctrl+O Ctrl+B"
                act_line = "Act: Ctrl+P a e Ctrl+S Esc l [ ] o v g 6"
                header_lines = [
                    "SeedPass ◈ TUI v2",
                    f"Fingerprint: {current_fp}",
                    f"Path: {self._session_breadcrumb_text()}",
                    (
                        "Session: "
                        f"{session_state} | Profiles: {profiles_loaded} | Managed: {managed_state}"
                    ),
                    (
                        "Scope: "
                        f"filter={self.filter_kind} arch={self.archive_scope} "
                        f"links={self.link_relation_filter}"
                    ),
                    self._selected_summary(),
                    (
                        f"Results: {len(self._all_results)} | "
                        f"Page: {self._result_page + 1}/{self._total_pages()}"
                    ),
                ]
            else:
                nav_line = "Nav: / j f(menu) Shift+F(cycle) h p/n 1/2/3 ↑/↓ Ctrl+O Ctrl+B ? r x"
                act_line = "Act: Ctrl+P a e Ctrl+S Esc l [ ] o v g 6 (v confirm for seed/ssh/pgp)"
                header_lines = [
                    "SeedPass ◈ TUI v2",
                    fp_line,
                    f"Path: {self._session_breadcrumb_text()}",
                    f"Profiles: {profiles_loaded}",
                    "",
                    self._selected_summary(),
                    f"Filter : {self.filter_kind}",
                    f"Archive: {self.archive_scope}",
                    f"Links  : {self.link_relation_filter}",
                    f"Density: {self._density_mode}",
                    f"Session: {session_state}",
                    f"Managed: {managed_state}",
                    (
                        f"Results: {len(self._all_results)} | "
                        f"Page: {self._result_page + 1}/{self._total_pages()}"
                    ),
                ]
            text = "\n".join(
                [
                    *header_lines,
                    "",
                    *tree_lines,
                    "",
                    nav_line,
                    act_line,
                ]
            )
            self.query_one("#filters", Static).update(text)
            self._update_top_ribbon()
            self._update_action_strip()
            self._update_grid_heading()

        def _render_entry_label(
            self,
            idx: int,
            label: str,
            etype: str,
            archived: bool,
            username: str | None = None,
            url: str | None = None,
        ) -> str:
            entry_num = idx
            title_limit = 27 if self._density_mode == "compact" else 36
            meta_limit = 24 if self._density_mode == "compact" else 34
            title_width = title_limit
            meta_width = meta_limit
            title = (label or "").replace("\n", " ").strip()[:title_limit]
            kind = (etype or "unknown")[:14]
            if url:
                meta = str(url).replace("\n", " ").strip()
            elif username:
                meta = str(username).replace("\n", " ").strip()
            else:
                meta = "-"
            reason = self._search_reason_by_id.get(int(idx), "")
            if reason == "semantic":
                meta = f"sem:{meta}"
            elif reason == "hybrid":
                meta = f"mix:{meta}"
            meta = meta[:meta_limit]
            arch = "YES" if archived else "NO"
            selected = "▌" if self._selected_entry_id == idx else " "
            return (
                f"{selected} {idx:<6} | {entry_num:<6} | {title:<{title_width}} | "
                f"{kind:<14} | {meta:<{meta_width}} | {arch:<3}"
            )

        def _total_pages(self) -> int:
            _page, _start, _end, total_pages = pagination_window(
                len(self._all_results), self.RESULT_PAGE_SIZE, self._result_page
            )
            return total_pages

        def _stats_text(self) -> str:
            lines = ["Vault Stats", "----------", ""]
            stats_payload: dict[str, Any] | None = None
            if self._vault_service is not None:
                getter = getattr(self._vault_service, "stats", None)
                if callable(getter):
                    try:
                        payload = getter()
                        if isinstance(payload, dict):
                            stats_payload = payload
                    except Exception:
                        stats_payload = None

            if isinstance(stats_payload, dict):
                total = int(stats_payload.get("total_entries", 0))
                lines.append(f"Total entries: {total}")
                entries = stats_payload.get("entries")
                if isinstance(entries, dict) and entries:
                    lines.append("Kinds:")
                    for kind, count in sorted(entries.items()):
                        lines.append(f"- {kind}: {count}")
                lines.append(
                    f"Relays configured: {int(stats_payload.get('relay_count', 0))}"
                )
                lines.append(f"Backups: {int(stats_payload.get('backup_count', 0))}")
                lines.append(
                    f"Schema version: {stats_payload.get('schema_version', '(unknown)')}"
                )
                lines.append(
                    "Database checksum ok: "
                    + ("yes" if bool(stats_payload.get("checksum_ok", False)) else "no")
                )
                lines.append(
                    "Script checksum ok: "
                    + (
                        "yes"
                        if bool(stats_payload.get("script_checksum_ok", False))
                        else "no"
                    )
                )
                lines.append(
                    f"Snapshot chunks: {int(stats_payload.get('chunk_count', 0))}"
                )
                lines.append(
                    f"Pending deltas: {int(stats_payload.get('pending_deltas', 0))}"
                )
                delta_since = stats_payload.get("delta_since")
                if delta_since:
                    lines.append(f"Latest delta timestamp: {delta_since}")
                return "\n".join(lines)

            if self._service is None:
                lines.append("Stats unavailable: entry service unavailable.")
                return "\n".join(lines)
            try:
                rows = self._service.search_entries(
                    "",
                    kinds=None,
                    include_archived=True,
                    archived_only=False,
                )
            except Exception as exc:
                lines.append(f"Stats unavailable: {exc}")
                return "\n".join(lines)

            total = len(rows)
            archived = sum(1 for row in rows if bool(row[4]))
            counts: dict[str, int] = {}
            for _idx, _label, _u, _url, _archived, etype in rows:
                kind = getattr(etype, "value", str(etype))
                counts[kind] = counts.get(kind, 0) + 1

            lines.append(f"Total entries: {total}")
            lines.append(f"Archived entries: {archived}")
            lines.append(f"Active entries: {max(0, total - archived)}")
            if counts:
                lines.append("Kinds:")
                for kind, count in sorted(counts.items()):
                    lines.append(f"- {kind}: {count}")
            lines.append("")
            lines.append("Tip: connect vault service for full operational stats.")
            return "\n".join(lines)

        def _render_current_page(self, *, preserve_selected: bool = True) -> None:
            self._entry_ids_in_view = []
            list_view = self.query_one("#entry-list", ListView)
            list_view.clear()
            total = len(self._all_results)
            if total == 0:
                try:
                    list_view.index = None
                except Exception:
                    pass
                self._selected_entry_id = None
                self._selected_entry = None
                is_empty_vault = (
                    not self._last_query.strip()
                    and self.filter_kind == "all"
                    and self.archive_scope == "active"
                )
                if is_empty_vault:
                    self.query_one("#entry-detail", Static).update(
                        self._onboarding_text()
                    )
                else:
                    self.query_one("#entry-detail", Static).update("No entries match.")
                self.query_one("#link-detail", Static).update(
                    "Links: select an entry first."
                )
                self._set_secret_panel(
                    "Sensitive data hidden. Select an entry, then use 'v' (reveal) or 'g' (QR)."
                )
                self._set_inspector_side_visible(False)
                self._current_links = []
                self._current_link_cursor = 0
                if is_empty_vault:
                    self._set_status(
                        "Vault is empty. Run 'onboarding' (or 'quickstart') to begin."
                    )
                else:
                    self._set_status("No entries match current filter/search")
                self._update_filters_panel()
                self._refresh_layout_balance()
                return

            self._result_page, start, end, _total_pages = pagination_window(
                total, self.RESULT_PAGE_SIZE, self._result_page
            )
            page_rows = self._all_results[start:end]
            for idx, label, username, url, archived, etype in page_rows:
                kind = getattr(etype, "value", str(etype))
                item = EntryListItem(
                    idx,
                    self._render_entry_label(
                        idx,
                        label,
                        kind,
                        bool(archived),
                        username=username,
                        url=url,
                    ),
                )
                self._entry_ids_in_view.append(int(idx))
                list_view.append(item)

            self._update_filters_panel()
            chosen_id = None
            if preserve_selected and self._selected_entry_id in self._entry_ids_in_view:
                chosen_id = self._selected_entry_id
            if chosen_id is not None:
                self._show_entry(chosen_id)
                return
            self._selected_entry_id = None
            self._selected_entry = None
            self.query_one("#entry-detail", Static).update(
                "Inspector idle.\n\nSelect an entry from the grid to inspect details."
            )
            self.query_one("#link-detail", Static).update(
                "Links: select an entry first."
            )
            self._set_secret_panel(
                "Sensitive data hidden. Select an entry, then use 'v' (reveal) or 'g' (QR)."
            )
            self._set_inspector_side_visible(False)
            self._current_links = []
            self._current_link_cursor = 0
            try:
                list_view.index = None
            except Exception:
                pass
            self._set_status("Entries loaded. Select an entry to inspect.")
            self._update_filters_panel()
            self._refresh_layout_balance()

        def _entry_detail_text(self, entry: dict[str, Any]) -> str:
            payload = truncate_entry_for_display(
                entry, self.DETAIL_CONTENT_PREVIEW_LIMIT
            )
            return self._entry_board_text(payload)

        @staticmethod
        def _entry_kind(entry: dict[str, Any]) -> str:
            token = (
                str(entry.get("kind") or entry.get("type") or "unknown").strip().lower()
            )
            return token.replace("-", "_").replace(" ", "_")

        @staticmethod
        def _entry_uses_sensitive_panel(kind: str) -> bool:
            return kind in {
                "password",
                "stored_password",
                "seed",
                "managed_account",
                "totp",
                "ssh",
                "pgp",
                "nostr",
            }

        def _apply_entry_inspector_visibility(
            self, entry: dict[str, Any] | None
        ) -> None:
            if not isinstance(entry, dict):
                self._set_inspector_side_visible(False)
                return
            self._set_inspector_side_visible(True)
            secret_detail = self.query_one("#secret-detail", Static)
            kind = self._entry_kind(entry)
            if self._entry_uses_sensitive_panel(kind):
                secret_detail.remove_class("hidden")
            else:
                secret_detail.add_class("hidden")

        @staticmethod
        def _entry_tags_text(entry: dict[str, Any]) -> str:
            tags = entry.get("tags")
            if isinstance(tags, list) and tags:
                return ", ".join(str(tag).strip() for tag in tags if str(tag).strip())
            if isinstance(tags, str) and tags.strip():
                return tags.strip()
            return "(none)"

        @staticmethod
        def _entry_notes_text(entry: dict[str, Any]) -> str:
            notes = entry.get("notes")
            if isinstance(notes, str) and notes.strip():
                return notes.strip()
            return "(none)"

        def _notes_tags_panel_hint(
            self, *, tags_text: str, notes_text: str
        ) -> list[str]:
            if self._dense_hires_layout:
                return ["Tags/Notes: side panel."]
            if not self._compact_layout:
                return ["Tags/Notes appear in right panel."]
            tags_preview = tags_text if len(tags_text) <= 88 else f"{tags_text[:85]}..."
            notes_preview = (
                notes_text if len(notes_text) <= 88 else f"{notes_text[:85]}..."
            )
            return [
                f"Tags: {tags_preview}",
                f"Notes: {notes_preview}",
            ]

        @staticmethod
        def _board_card(
            title: str, rows: list[str], *, max_width: int = 72
        ) -> list[str]:
            natural = max([len(title), *[len(row) for row in rows], 12])
            width = min(natural, max_width)
            capped_rows = [
                r if len(r) <= width else f"{r[: width - 1]}\u2026" for r in rows
            ]
            top = f"+- {title} " + "-" * max(1, width - len(title) - 2) + "+"
            body = [f"| {row.ljust(width)} |" for row in capped_rows]
            bottom = "+" + "-" * (width + 2) + "+"
            return [top, *body, bottom]

        def _entry_board_header(self, entry: dict[str, Any]) -> list[str]:
            entry_id = (
                self._selected_entry_id
                if self._selected_entry_id is not None
                else entry.get("id", "?")
            )
            label = str(entry.get("label") or "(untitled)")
            kind = self._entry_kind(entry) or "unknown"
            icon = self._kind_icon(kind)
            modified = str(
                entry.get("modified_at")
                or entry.get("updated_at")
                or entry.get("date_modified")
                or "(unknown)"
            )
            archived = "Yes" if bool(entry.get("archived", False)) else "No"
            index_num = str(entry.get("index", "(auto)"))
            title = f"{icon} Entry #{entry_id}  {label}"
            return [
                title,
                "-" * max(24, len(title)),
                f"Kind: {kind} | Modified: {modified} | Archived: {archived}",
                f"Index Num*: {index_num} | Entry Num: {entry_id} | Edit: e",
            ]

        def _entry_board_text(self, entry: dict[str, Any]) -> str:
            kind = self._entry_kind(entry)
            header = self._entry_board_header(entry)
            tags_text = self._entry_tags_text(entry)
            notes_text = self._entry_notes_text(entry)

            if kind in {"password", "stored_password"}:
                username = str(entry.get("username") or "(none)")
                url = str(entry.get("url") or "(none)")
                length = str(entry.get("length") or "(auto)")
                board_name = "Stored Password Board"
                action_row = "▣ Copy Password  ▣ Edit"
                if kind == "password":
                    board_name = "Password Board"
                    action_row = "▣ Copy Password  ▣ Create New  ▣ Edit"
                entry_id = (
                    self._selected_entry_id
                    if self._selected_entry_id is not None
                    else entry.get("id", "?")
                )
                modified = str(
                    entry.get("modified_at")
                    or entry.get("updated_at")
                    or entry.get("date_modified")
                    or "(unknown)"
                )
                archived = "Yes" if bool(entry.get("archived", False)) else "No"
                index_num = str(entry.get("index", "(auto)"))
                label = str(entry.get("label") or "(untitled)")
                credential_rows = [
                    "Password*: hidden (v reveal, g qr)",
                    f"Username*: {username}",
                    f"URL      : {url}",
                    f"Length   : {length} chars",
                ]
                operation_rows = [action_row]
                lines = [
                    f"Entry #{entry_id}  {label}",
                    "-" * max(24, len(label) + 10),
                    f"{self._kind_icon(kind)} {board_name}",
                    f"Kind: {kind} | Modified: {modified} | Archived: {archived}",
                    f"Index Num*: {index_num}",
                    *self._board_card("Credentials", credential_rows),
                    *self._board_card("Quick Actions", operation_rows),
                    *self._notes_tags_panel_hint(
                        tags_text=tags_text, notes_text=notes_text
                    ),
                    (
                        "Actions: e edit | a archive"
                        if self._dense_hires_layout
                        else "Actions: Edit (e) | Archive (a)"
                    ),
                ]
                return "\n".join(lines)

            if kind in {"document", "note"}:
                file_type = str(entry.get("file_type") or "txt")
                content = str(entry.get("content") or "")
                preview = content.strip()
                if preview:
                    preview = preview.replace("\n", " ")[:100]
                else:
                    preview = "(empty)"
                entry_id = (
                    self._selected_entry_id
                    if self._selected_entry_id is not None
                    else entry.get("id", "?")
                )
                modified = str(
                    entry.get("modified_at")
                    or entry.get("updated_at")
                    or entry.get("date_modified")
                    or "(unknown)"
                )
                archived = "Yes" if bool(entry.get("archived", False)) else "No"
                index_num = str(entry.get("index", "(auto)"))
                document_rows = [
                    f"Content Length: {len(content)} chars",
                    f"Preview       : {preview}",
                ]
                lines = [
                    f"Entry #{entry_id}  {str(entry.get('label') or '(untitled)')}",
                    "-" * 28,
                    f"{self._kind_icon(kind)} Note Board",
                    f"Kind: {kind} | Modified: {modified} | Archived: {archived}",
                    f"Index Num*: {index_num} | File Type: {file_type}",
                    *self._board_card("Content", document_rows),
                    *self._board_card("Quick Actions", ["▣ Edit  ▣ Export"]),
                    *self._notes_tags_panel_hint(
                        tags_text=tags_text, notes_text=notes_text
                    ),
                    (
                        "Actions: e edit | Ctrl+S save | Esc cancel | a archive"
                        if self._dense_hires_layout
                        else "Actions: Edit (e) | Save (Ctrl+S) | Cancel (Esc) | Archive (a)"
                    ),
                ]
                return "\n".join(lines)

            if kind in {"seed", "managed_account"}:
                phrase_text = str(entry.get("seed_phrase") or "").strip()
                words_value = entry.get("words")
                if words_value is None and phrase_text:
                    words_value = len([w for w in phrase_text.split() if w.strip()])
                words = str(words_value or "(unknown)")
                index = str(entry.get("index") or "(auto)")
                board_name = (
                    "Managed Account Seed Board"
                    if kind == "managed_account"
                    else "BIP-39 Seed Board"
                )
                seed_rows = [
                    f"Seed Phrase*: hidden (v confirm) | Word Count: {words}",
                    f"Index Num*: {index}",
                ]
                operation_rows = [
                    "▣ Reveal Seed  ▣ QR Seed  ▣ Copy Seed(confirm)  ▣ Export Seed(confirm)",
                ]
                lines = header + [
                    f"{self._kind_icon(kind)} {board_name}",
                    *self._board_card("Seed Info", seed_rows),
                    *self._board_card("Quick Actions", operation_rows),
                    *self._notes_tags_panel_hint(
                        tags_text=tags_text, notes_text=notes_text
                    ),
                    (
                        "Actions: v reveal(cfm) | g qr | copy seed cfm | export cfm | a archive"
                        if self._dense_hires_layout
                        else "Actions: Reveal (v cfm) | QR (g) | Copy (cfm) | Export (cfm) | Archive (a)"
                    ),
                ]
                return "\n".join(lines)

            if kind == "totp":
                period = str(entry.get("period") or 30)
                digits = str(entry.get("digits") or 6)
                label = str(entry.get("label") or "(untitled)")
                entry_id = (
                    self._selected_entry_id
                    if self._selected_entry_id is not None
                    else entry.get("id", "?")
                )
                modified = str(
                    entry.get("modified_at")
                    or entry.get("updated_at")
                    or entry.get("date_modified")
                    or "(unknown)"
                )
                archived = "Yes" if bool(entry.get("archived", False)) else "No"
                index_num = str(entry.get("index", "(auto)"))
                field_rows = [
                    f"Period : {period}s",
                    f"Digits : {digits}",
                    "Current Code: hidden (use '6' board or 'v' reveal)",
                    "Secret: hidden | URI via QR",
                ]
                operation_rows = [
                    "▣ Copy Code  ▣ Copy URL(confirm)  ▣ Reveal Secret  ▣ QR",
                ]
                lines = [
                    f"Entry #{entry_id}  {label}",
                    "-" * 28,
                    f"{self._kind_icon(kind)} 2FA Board",
                    f"Kind: {kind} | Modified: {modified} | Archived: {archived}",
                    f"Index Num*: {index_num}",
                    *self._board_card("Parameters", field_rows),
                    *self._board_card("Quick Actions", operation_rows),
                    *self._notes_tags_panel_hint(
                        tags_text=tags_text, notes_text=notes_text
                    ),
                    (
                        "Actions: 6 board | 2fa-copy | 2fa-copy-url | v reveal | g qr | a archive"
                        if self._dense_hires_layout
                        else "Actions: 2FA Board (6) | Copy Code | Copy URL | Reveal (v) | QR (g) | Archive (a)"
                    ),
                ]
                return "\n".join(lines)

            if kind == "ssh":
                public_preview = str(entry.get("public_key") or "(unavailable)")
                public_preview = public_preview.replace("\n", " ").strip()
                public_preview = (
                    f"{public_preview[:72]}..."
                    if len(public_preview) > 72
                    else public_preview
                )
                label = str(entry.get("label") or "(untitled)")
                entry_id = (
                    self._selected_entry_id
                    if self._selected_entry_id is not None
                    else entry.get("id", "?")
                )
                modified = str(
                    entry.get("modified_at")
                    or entry.get("updated_at")
                    or entry.get("date_modified")
                    or "(unknown)"
                )
                archived = "Yes" if bool(entry.get("archived", False)) else "No"
                index_num = str(entry.get("index", "(auto)"))
                key_rows = [
                    f"Public Key: {public_preview}",
                    "Private Key: hidden (use 'v confirm' to reveal)",
                ]
                operation_rows = [
                    "▣ Copy Public  ▣ Export Public",
                    "▣ Reveal Private  ▣ Copy Private  ▣ Export Private",
                ]
                lines = [
                    f"Entry #{entry_id}  {label}",
                    "-" * 28,
                    f"{self._kind_icon(kind)} SSH Board",
                    f"Kind: ssh | Modified: {modified} | Archived: {archived}",
                    f"Index Num*: {index_num} | Entry Num: {entry_id}",
                    *self._board_card("Keys", key_rows),
                    *self._board_card("Quick Actions", operation_rows),
                    *self._notes_tags_panel_hint(
                        tags_text=tags_text, notes_text=notes_text
                    ),
                    (
                        "Actions: v reveal | e edit | a archive | Ctrl+P copy/export-field"
                        if self._dense_hires_layout
                        else "Actions: Reveal (v) | Edit (e) | Archive (a) | Ctrl+P copy/export-field"
                    ),
                ]
                return "\n".join(lines)

            if kind == "pgp":
                fingerprint_text = str(entry.get("fingerprint") or "(unknown)")
                label = str(entry.get("label") or "(untitled)")
                entry_id = (
                    self._selected_entry_id
                    if self._selected_entry_id is not None
                    else entry.get("id", "?")
                )
                modified = str(
                    entry.get("modified_at")
                    or entry.get("updated_at")
                    or entry.get("date_modified")
                    or "(unknown)"
                )
                archived = "Yes" if bool(entry.get("archived", False)) else "No"
                index_num = str(entry.get("index", "(auto)"))
                key_rows = [
                    f"Fingerprint: {fingerprint_text}",
                    "Public Key: available",
                    "Private Key: hidden (use 'v confirm' to reveal)",
                ]
                operation_rows = [
                    "▣ Copy Public  ▣ Export Public",
                    "▣ Reveal Private  ▣ Copy Private  ▣ Export Private",
                ]
                lines = [
                    f"Entry #{entry_id}  {label}",
                    "-" * 28,
                    f"{self._kind_icon(kind)} PGP Board",
                    f"Kind: pgp | Modified: {modified} | Archived: {archived}",
                    f"Index Num*: {index_num} | Entry Num: {entry_id}",
                    *self._board_card("Keys", key_rows),
                    *self._board_card("Quick Actions", operation_rows),
                    *self._notes_tags_panel_hint(
                        tags_text=tags_text, notes_text=notes_text
                    ),
                    (
                        "Actions: v reveal | e edit | a archive | Ctrl+P copy/export-field"
                        if self._dense_hires_layout
                        else "Actions: Reveal (v) | Edit (e) | Archive (a) | Ctrl+P copy/export-field"
                    ),
                ]
                return "\n".join(lines)

            if kind == "nostr":
                npub = str(entry.get("npub") or "(unavailable)")
                label = str(entry.get("label") or "(untitled)")
                entry_id = (
                    self._selected_entry_id
                    if self._selected_entry_id is not None
                    else entry.get("id", "?")
                )
                modified = str(
                    entry.get("modified_at")
                    or entry.get("updated_at")
                    or entry.get("date_modified")
                    or "(unknown)"
                )
                archived = "Yes" if bool(entry.get("archived", False)) else "No"
                index_num = str(entry.get("index", "(auto)"))
                key_rows = [
                    f"npub: {npub}",
                    "nsec: hidden (use 'v confirm' to reveal)",
                ]
                operation_rows = [
                    "▣ Copy npub  ▣ Copy nsec  ▣ Edit",
                    "▣ QR Public  ▣ QR Private",
                ]
                lines = [
                    f"Entry #{entry_id}  {label}",
                    "-" * 28,
                    f"{self._kind_icon(kind)} Nostr Board",
                    f"Kind: nostr | Modified: {modified} | Archived: {archived}",
                    f"Index Num*: {index_num} | Entry Num: {entry_id}",
                    *self._board_card("Keys", key_rows),
                    *self._board_card("Quick Actions", operation_rows),
                    *self._notes_tags_panel_hint(
                        tags_text=tags_text, notes_text=notes_text
                    ),
                    (
                        "Actions: v reveal | g qr | QR Private (cfm) | a archive"
                        if self._dense_hires_layout
                        else "Actions: Reveal (v) | QR (g) | QR Private (confirm) | Archive (a)"
                    ),
                ]
                return "\n".join(lines)

            if kind == "key_value":
                key_name = str(entry.get("key") or "(none)")
                value = str(entry.get("value") or "")
                value_preview = value[:80] + ("..." if len(value) > 80 else "")
                lines = header + [
                    "Key/Value",
                    f"- Key: {key_name}",
                    f"- Value: {value_preview if value_preview else '(empty)'}",
                    "",
                    "Tags",
                    f"- {tags_text}",
                    "",
                    "Notes",
                    notes_text,
                ]
                return "\n".join(lines)

            entry_id = (
                self._selected_entry_id
                if self._selected_entry_id is not None
                else entry.get("id", "?")
            )
            fallback_kind = entry.get("kind") or entry.get("type") or "unknown"
            title = f"Entry #{entry_id}  [{fallback_kind}]"
            return (
                f"{title}\n{'-' * len(title)}\n"
                f"{json.dumps(entry, indent=2, sort_keys=True)}"
            )

        def _entry_kind_from_row(self, row: tuple[Any, ...]) -> str:
            if len(row) < 6:
                return ""
            kind_obj = row[5]
            return str(getattr(kind_obj, "value", kind_obj)).strip().lower()

        def _search_rows_with_semantic(
            self,
            *,
            query: str,
            include_archived: bool,
            archived_only: bool,
        ) -> tuple[list[tuple[Any, ...]], dict[int, str]]:
            rows = list(
                self._service.search_entries(
                    query,
                    kinds=self._current_filter_kinds(),
                    include_archived=include_archived,
                    archived_only=archived_only,
                )
            )
            reasons: dict[int, str] = {}
            for row in rows:
                if len(row) >= 1:
                    reasons[int(row[0])] = "keyword"

            mode = str(self._semantic_mode or "keyword").strip().lower()
            if not query.strip() or mode == "keyword" or self._semantic_service is None:
                return rows, reasons

            searcher = getattr(self._semantic_service, "search", None)
            if not callable(searcher):
                return rows, reasons

            kind_filter = self._current_filter_kinds()
            semantic_rows: list[tuple[Any, ...]] = []
            try:
                matches = list(searcher(query, k=50, kind=None, mode=mode) or [])
            except Exception:
                return rows, reasons

            for match in matches:
                try:
                    entry_id = int(match.get("entry_id", 0))
                except Exception:
                    continue
                if entry_id <= 0:
                    continue
                try:
                    entry = self._service.retrieve_entry(entry_id)
                except Exception:
                    continue
                if not isinstance(entry, dict) or not entry:
                    continue
                kind = str(entry.get("kind") or entry.get("type") or "").strip().lower()
                if kind_filter and kind not in kind_filter:
                    continue
                archived = bool(entry.get("archived", False))
                if archived_only and not archived:
                    continue
                if not include_archived and archived:
                    continue
                label = str(
                    entry.get("label") or match.get("label") or f"entry-{entry_id}"
                )
                username = entry.get("username")
                url = entry.get("url")
                semantic_rows.append(
                    (
                        entry_id,
                        label,
                        username,
                        url,
                        archived,
                        SimpleNamespace(value=kind or "unknown"),
                    )
                )
                current = reasons.get(entry_id)
                reasons[entry_id] = "hybrid" if current == "keyword" else "semantic"

            if mode == "semantic":
                dedup: dict[int, tuple[Any, ...]] = {}
                for row in semantic_rows:
                    dedup[int(row[0])] = row
                return list(dedup.values()), reasons

            # Hybrid mode: keyword rows first, then semantic-only rows.
            known_ids = {int(row[0]) for row in rows if len(row) >= 1}
            for row in semantic_rows:
                entry_id = int(row[0])
                if entry_id in known_ids:
                    continue
                rows.append(row)
                known_ids.add(entry_id)
            return rows, reasons

        def _load_entries(self, query: str = "", *, reset_page: bool = False) -> None:
            self._last_query = query
            if self._service is None:
                self.query_one("#entry-detail", Static).update(
                    "Entry service unavailable in this runtime."
                )
                self.query_one("#link-detail", Static).update("Links unavailable.")
                self._set_secret_panel(
                    "Sensitive data unavailable: entry service missing."
                )
                self._set_inspector_side_visible(False)
                self._all_results = []
                self._search_reason_by_id = {}
                self._result_page = 0
                self._current_links = []
                self._current_link_cursor = 0
                self._update_filters_panel()
                return

            try:
                include_archived, archived_only = self._current_archive_scope_flags()
                results, reasons = self._search_rows_with_semantic(
                    query=query,
                    include_archived=include_archived,
                    archived_only=archived_only,
                )
            except Exception as exc:
                self.query_one("#entry-detail", Static).update(
                    f"Failed to load entries: {exc}"
                )
                self.query_one("#link-detail", Static).update("Links unavailable.")
                self._set_secret_panel(
                    "Sensitive data unavailable: failed to load entries."
                )
                self._set_inspector_side_visible(False)
                self._all_results = []
                self._search_reason_by_id = {}
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
            self._search_reason_by_id = dict(reasons)
            self._clear_failure()
            if reset_page:
                self._result_page = 0
            self._render_current_page(preserve_selected=not reset_page)

        def _show_entry(self, entry_index: int) -> None:
            if self._session_locked:
                self._set_status("Vault is locked. Run: unlock <password>")
                return
            if self.editing_document:
                self._set_status("Finish document edit before opening another entry")
                return
            if self._service is None:
                return
            if self.totp_board_open:
                self._set_totp_board_visible(False)
            try:
                entry = self._service.retrieve_entry(entry_index)
                if not isinstance(entry, dict) or not entry:
                    self.query_one("#entry-detail", Static).update(
                        f"Entry #{entry_index} not found.\n\nThe entry may have been deleted or the ID is invalid."
                    )
                    self.query_one("#link-detail", Static).update(
                        "Links: entry not found."
                    )
                    self._current_links = []
                    self._current_link_cursor = 0
                    self._selected_entry_id = None
                    self._selected_entry = None
                    self._update_action_strip()
                    self._set_status(f"Entry {entry_index} not found")
                    return
                self._selected_entry_id = int(entry_index)
                self._selected_entry = dict(entry)
                self._pending_sensitive_confirm = None
                body = self._entry_detail_text(entry)
                self.query_one("#entry-detail", Static).update(body)
                kind = self._entry_kind(entry)
                if self._entry_uses_sensitive_panel(kind):
                    self._set_secret_panel(
                        "Sensitive data hidden. Use 'v' to reveal 🔑 or 'g' for QR ▦."
                    )
                else:
                    self._set_secret_panel(
                        "No sensitive reveal for this entry kind.", state=None
                    )
                self._apply_entry_inspector_visibility(entry)
                self._update_inspector_heading()
                self._update_links_panel()
                self._update_filters_panel()
                self._set_status(f"Selected entry {entry_index}")
                self._refresh_layout_balance()
            except Exception as exc:
                self.query_one("#entry-detail", Static).update(
                    f"Failed to load entry {entry_index}: {exc}"
                )
                self.query_one("#link-detail", Static).update("Links unavailable.")
                self._set_secret_panel(
                    "Sensitive data unavailable: failed to load selected entry."
                )
                self._apply_entry_inspector_visibility(None)
                self._update_inspector_heading()
                self._current_links = []
                self._current_link_cursor = 0
                self._record_failure(
                    f"Failed to load entry {entry_index}",
                    exc,
                    retry=lambda: self._show_entry(entry_index),
                    hint="Press 'x' to retry.",
                )
                self._refresh_layout_balance()

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

            tags_text = "(none)"
            notes_text = "(none)"
            if isinstance(self._selected_entry, dict):
                tags_text = self._entry_tags_text(self._selected_entry)
                notes_text = self._entry_notes_text(self._selected_entry)

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

            notes_preview = notes_text[:220]
            kind = self._selected_kind()
            side_title = (
                "Notes & Tags"
                if kind
                in {
                    "password",
                    "stored_password",
                    "document",
                    "note",
                    "totp",
                    "seed",
                    "managed_account",
                    "ssh",
                    "pgp",
                    "nostr",
                    "key_value",
                }
                else "Links & Context"
            )
            notes_only_kinds = {
                "password",
                "stored_password",
                "document",
                "note",
                "totp",
                "seed",
                "managed_account",
                "ssh",
                "pgp",
                "nostr",
                "key_value",
            }

            if kind in notes_only_kinds:
                lines = [
                    f"{side_title} #{self._selected_entry_id}",
                    "-" * 28,
                    f"Tags: {tags_text}",
                    f"Notes: {notes_preview if notes_preview.strip() else '(none)'}",
                ]
                if links:
                    for i, link in enumerate(self._current_links):
                        target = link.get("target")
                        relation = link.get("relation", "related_to")
                        note = str(link.get("note", "")).strip()
                        prefix = ">" if i == self._current_link_cursor else " "
                        if note:
                            lines.append(f"{prefix} {relation} -> {target} ({note})")
                        else:
                            lines.append(f"{prefix} {relation} -> {target}")
                    lines.extend(
                        [
                            "",
                            f"Graph links: {len(links)}",
                            "Use Ctrl+P: link-add/link-rm/link-open",
                        ]
                    )
                else:
                    lines.extend(
                        [
                            "",
                            "No graph links for this entry.",
                            "Use Ctrl+P: link-add <target_id> [relation] [note]",
                        ]
                    )
                self.query_one("#link-detail", Static).update("\n".join(lines))
                return

            if not links:
                self.query_one("#link-detail", Static).update(
                    (
                        f"{side_title} #{self._selected_entry_id}\n"
                        f"{'-' * 28}\n"
                        "No graph links for this entry.\n"
                        "Use Ctrl+P: link-add <target_id> [relation] [note]\n\n"
                        "Tags\n"
                        f"{tags_text}\n\n"
                        "Notes\n"
                        f"{notes_preview}"
                    )
                )
                return
            if not filtered:
                self.query_one("#link-detail", Static).update(
                    (
                        f"{side_title} #{self._selected_entry_id}\n"
                        f"{'-' * 28}\n"
                        f"Relation filter: {self.link_relation_filter}\n\n"
                        "No links match this relation filter.\n"
                        "Press 'l' to cycle relation filter.\n\n"
                        "Tags\n"
                        f"{tags_text}\n\n"
                        "Notes\n"
                        f"{notes_preview}"
                    )
                )
                return

            lines = [
                f"{side_title} #{self._selected_entry_id}",
                "-" * 28,
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
            lines.extend(
                [
                    "",
                    "Tags",
                    tags_text,
                    "",
                    "Notes",
                    notes_preview,
                ]
            )
            self.query_one("#link-detail", Static).update("\n".join(lines))
            self._clear_failure()

        def _is_selected_document(self) -> bool:
            if not isinstance(self._selected_entry, dict):
                return False
            kind = str(
                self._selected_entry.get("kind") or self._selected_entry.get("type")
            )
            return kind == "document"

        def _selected_kind(self) -> str:
            if not isinstance(self._selected_entry, dict):
                return ""
            return (
                str(
                    self._selected_entry.get("kind")
                    or self._selected_entry.get("type")
                    or ""
                )
                .strip()
                .lower()
            )

        @staticmethod
        def _kind_icon(kind: str) -> str:
            return {
                "password": "🗝",
                "totp": "📱",
                "ssh": "🖧",
                "pgp": "🔒",
                "nostr": "⚡",
                "document": "📄",
                "managed_account": "👥",
                "seed": "🌱",
            }.get(kind, "•")

        def _is_secret_mode_enabled(self) -> bool:
            if self._service is None:
                return False
            getter = getattr(self._service, "get_secret_mode_enabled", None)
            if not callable(getter):
                return False
            try:
                return bool(getter())
            except Exception:
                return False

        def _clipboard_clear_delay(self) -> int:
            if self._service is None:
                return 30
            getter = getattr(self._service, "get_clipboard_clear_delay", None)
            if not callable(getter):
                return 30
            try:
                return int(getter())
            except Exception:
                return 30

        def _copy_to_clipboard(self, value: str) -> bool:
            if self._service is None:
                return False
            copier = getattr(self._service, "copy_to_clipboard", None)
            if not callable(copier):
                return False
            try:
                return bool(copier(value))
            except Exception:
                return False

        def _resolve_selected_sensitive_payload(
            self, *, qr_mode: str = "default"
        ) -> tuple[str, str, str | None, str | None, str]:
            if self._service is None:
                raise ValueError("Entry service unavailable")
            if self._selected_entry_id is None:
                raise ValueError("No entry selected")

            entry = self._selected_entry or self._service.retrieve_entry(
                self._selected_entry_id
            )
            if not isinstance(entry, dict) or not entry:
                raise ValueError("Selected entry not found")

            kind = (
                self._selected_kind()
                or str(entry.get("kind") or entry.get("type") or "").strip().lower()
            )
            label = str(entry.get("label", f"entry-{self._selected_entry_id}"))
            icon = self._kind_icon(kind)

            if kind == "password":
                length = int(entry.get("length", 16))
                password = self._service.generate_password(
                    length, self._selected_entry_id
                )
                return (
                    f"Sensitive {icon}: Password #{self._selected_entry_id}",
                    f"Label : {label}\nPassword : {password}",
                    None,
                    password,
                    kind,
                )

            if kind == "seed":
                phrase = self._service.get_seed_phrase(self._selected_entry_id)
                from seedpass.core.seedqr import encode_seedqr

                seedqr = encode_seedqr(phrase)
                return (
                    f"Sensitive {icon}: Seed #{self._selected_entry_id}",
                    f"Label : {label}\nSeed Phrase : {phrase}",
                    seedqr,
                    phrase,
                    kind,
                )

            if kind == "managed_account":
                phrase = self._service.get_managed_account_seed(self._selected_entry_id)
                from seedpass.core.seedqr import encode_seedqr

                seedqr = encode_seedqr(phrase)
                return (
                    f"Sensitive {icon}: Managed Account Seed #{self._selected_entry_id}",
                    f"Label : {label}\nSeed Phrase : {phrase}",
                    seedqr,
                    phrase,
                    kind,
                )

            if kind == "totp":
                secret = self._service.get_totp_secret(self._selected_entry_id)
                code = self._service.get_totp_code(self._selected_entry_id)
                period = int(entry.get("period", 30))
                digits = int(entry.get("digits", 6))
                from seedpass.core.totp import TotpManager

                uri = TotpManager.make_otpauth_uri(
                    label, secret, period=period, digits=digits
                )
                return (
                    f"Sensitive {icon}: TOTP #{self._selected_entry_id}",
                    (
                        f"Label : {label}\n"
                        f"Code : {code}\n"
                        f"Secret : {secret}\n"
                        f"Period : {period}s\n"
                        f"Digits : {digits}"
                    ),
                    uri,
                    code,
                    kind,
                )

            if kind == "ssh":
                priv_key, pub_key = self._service.get_ssh_key_pair(
                    self._selected_entry_id
                )
                return (
                    f"Sensitive {icon}: SSH #{self._selected_entry_id}",
                    f"Label : {label}\nPublic Key : {pub_key}\nPrivate Key : {priv_key}",
                    None,
                    priv_key,
                    kind,
                )

            if kind == "pgp":
                priv_key, _pub_key, fingerprint_text = self._service.get_pgp_key(
                    self._selected_entry_id
                )
                return (
                    f"Sensitive {icon}: PGP #{self._selected_entry_id}",
                    (
                        f"Label : {label}\n"
                        f"Fingerprint : {fingerprint_text}\n"
                        f"Private Key :\n{priv_key}"
                    ),
                    None,
                    priv_key,
                    kind,
                )

            if kind == "nostr":
                npub, nsec = self._service.get_nostr_key_pair(self._selected_entry_id)
                if qr_mode == "private":
                    qr_payload = nsec
                else:
                    qr_payload = f"nostr:{npub}"
                return (
                    f"Sensitive {icon}: Nostr #{self._selected_entry_id}",
                    f"Label : {label}\nnpub : {npub}\nnsec : {nsec}",
                    qr_payload,
                    nsec,
                    kind,
                )

            raise ValueError(
                "Reveal unsupported for kind "
                f"'{kind or 'unknown'}'. Supported: password, seed, managed_account, "
                "totp, ssh, pgp, nostr."
            )

        def _requires_confirm(
            self, *, kind: str, include_qr: bool, qr_mode: str
        ) -> bool:
            if include_qr:
                return kind == "nostr" and qr_mode == "private"
            return kind in {"seed", "managed_account", "ssh", "pgp"}

        def _consume_pending_sensitive_confirm(
            self, *, action: str, entry_id: int, ttl_seconds: float = 8.0
        ) -> bool:
            pending = self._pending_sensitive_confirm
            if pending is None:
                return False
            pending_action, pending_entry_id, ts = pending
            now = float(self._time_now())
            if (
                pending_action == action
                and int(pending_entry_id) == int(entry_id)
                and (now - float(ts)) <= ttl_seconds
            ):
                self._pending_sensitive_confirm = None
                return True
            self._pending_sensitive_confirm = None
            return False

        def _show_sensitive_panel(
            self, *, include_qr: bool, qr_mode: str = "default", confirm: bool = False
        ) -> None:
            try:
                title, body, qr_data, secret_value, kind = (
                    self._resolve_selected_sensitive_payload(qr_mode=qr_mode)
                )
            except Exception as exc:
                self._record_failure(
                    "Sensitive reveal failed",
                    exc,
                    retry=(
                        (lambda: self.action_show_qr(mode=qr_mode, confirm=confirm))
                        if include_qr
                        else (lambda: self.action_reveal_selected(confirm=confirm))
                    ),
                    hint="Press 'x' to retry.",
                )
                return

            if (
                self._requires_confirm(
                    kind=kind, include_qr=include_qr, qr_mode=qr_mode
                )
                and not confirm
            ):
                action_key = "g" if include_qr else "v"
                prompt = (
                    f"CONFIRMATION REQUIRED\n\n"
                    f"This is a high-risk action for kind '{kind}'.\n"
                    f"To proceed, press '{action_key}' again within 8s."
                )
                self._set_secret_panel(prompt, state="HIDDEN")
                self._set_status(
                    f"Sensitive action requires confirmation (press '{action_key}' again)"
                )

                self._pending_sensitive_confirm = (
                    "show_qr" if include_qr else "reveal_selected",
                    int(self._selected_entry_id),
                    self._time_now(),
                )
                return

            if include_qr:
                if not qr_data:
                    self._set_secret_panel(
                        f"{title}\n\nQR not supported for this entry.",
                        state="HIDDEN",
                    )
                    self._clear_failure()
                    self._set_status("QR not available for selected entry")
                    return
                try:
                    qr_ascii = render_qr_ascii(qr_data)
                except Exception as exc:
                    self._record_failure(
                        "QR render failed",
                        exc,
                        retry=self.action_show_qr,
                        hint="Press 'x' to retry.",
                    )
                    return
                self._set_secret_panel(
                    f"{title} QR\n\n{qr_ascii}\n\nPayload: {qr_data}",
                    state="QR",
                )
                self._clear_failure()
                self._set_status("Rendered QR for selected entry")
                return

            self._set_secret_panel(f"{title}\n\n{body}", state="REVEALED")
            self._clear_failure()
            if self._is_secret_mode_enabled() and secret_value:
                if self._copy_to_clipboard(secret_value):
                    delay = self._clipboard_clear_delay()
                    self._set_secret_panel(
                        f"{title}\n\nSecret mode is enabled.\n"
                        f"Sensitive value copied to clipboard (auto-clear in {delay}s).",
                        state="COPIED",
                    )
                    self._set_status("Sensitive value copied to clipboard")
                    return
            self._set_status("Revealed selected sensitive data")

        def _set_document_editor_visible(self, visible: bool) -> None:
            self._set_right_pane_mode("edit" if visible else "view")
            self._focus_pane = "right"
            self._apply_focus_style()
            self._update_inspector_heading()

        def _set_right_pane_mode(self, mode: str) -> None:
            view = self.query_one("#right-view", Vertical)
            editor = self.query_one("#right-editor", Vertical)
            board = self.query_one("#totp-board", Static)
            settings_board = self.query_one("#settings-board", Static)
            entry_detail = self.query_one("#entry-detail", Static)
            mode_token = str(mode or "view").strip().lower()
            if mode_token == "edit":
                view.add_class("hidden")
                editor.remove_class("hidden")
                board.add_class("hidden")
                settings_board.add_class("hidden")
                entry_detail.remove_class("hidden")
                self.totp_board_open = False
                self.settings_open = False
                self.editing_document = True
                self._update_inspector_heading()
                self._refresh_layout_balance()
                return
            if mode_token == "totp":
                editor.add_class("hidden")
                view.remove_class("hidden")
                entry_detail.add_class("hidden")
                self._set_inspector_side_visible(False)
                board.remove_class("hidden")
                settings_board.add_class("hidden")
                self.totp_board_open = True
                self.settings_open = False
                self.editing_document = False
                self._refresh_totp_board(force_reload=True)
                self._update_inspector_heading()
                self._refresh_layout_balance()
                return
            if mode_token == "settings":
                editor.add_class("hidden")
                view.remove_class("hidden")
                entry_detail.add_class("hidden")
                self._set_inspector_side_visible(False)
                board.add_class("hidden")
                settings_board.remove_class("hidden")
                self.totp_board_open = False
                self.settings_open = True
                self.editing_document = False
                self._refresh_settings_board()
                self._update_inspector_heading()
                self._refresh_layout_balance()
                return
            # Default "view": entry board + side panels, no editor/2FA board.
            if mode_token not in {"view", "edit", "totp", "settings"}:
                mode_token = "view"
            if mode_token == "view":
                editor.add_class("hidden")
                view.remove_class("hidden")
                board.add_class("hidden")
                settings_board.add_class("hidden")
                entry_detail.remove_class("hidden")
                self._apply_entry_inspector_visibility(self._selected_entry)
                self.totp_board_open = False
                self.settings_open = False
                self.editing_document = False
                self._update_inspector_heading()
                self._refresh_layout_balance()

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

        def _set_totp_board_visible(self, visible: bool) -> None:
            if visible:
                self._set_right_pane_mode("totp")
            else:
                self._set_right_pane_mode("view")

        @staticmethod
        def _totp_source(entry: dict[str, Any]) -> str:
            deterministic = entry.get("deterministic")
            if isinstance(deterministic, bool):
                return "det" if deterministic else "imp"
            secret = str(entry.get("secret", "")).strip()
            return "imp" if secret else "det"

        def _load_totp_rows(self) -> None:
            if self._service is None:
                self._totp_rows = []
                return
            rows: list[dict[str, Any]] = []
            results = self._service.search_entries("", kinds=["totp"])
            for row in results:
                entry_id = int(row[0])
                label = str(row[1])
                entry = self._service.retrieve_entry(entry_id)
                if not isinstance(entry, dict):
                    continue
                period = int(entry.get("period", 30))
                digits = int(entry.get("digits", 6))
                rows.append(
                    {
                        "id": entry_id,
                        "label": label,
                        "period": period,
                        "digits": digits,
                        "source": self._totp_source(entry),
                    }
                )
            self._totp_rows = rows

        def _refresh_totp_board(self, *, force_reload: bool = False) -> None:
            if not self.totp_board_open:
                return
            if self._service is None:
                self.query_one("#totp-board", Static).update(
                    "2FA Board\n\nEntry service unavailable."
                )
                return
            try:
                if force_reload or not self._totp_rows:
                    self._load_totp_rows()
            except Exception as exc:
                self._record_failure(
                    "Failed to load 2FA board",
                    exc,
                    retry=lambda: self._refresh_totp_board(force_reload=True),
                    hint="Press 'x' to retry.",
                )
                return

            now = int(self._time_now())
            secret_mode = self._is_secret_mode_enabled()
            lines = [
                "2FA Board",
                "",
                "id  src  rem  code      label",
                "--  ---  ---  --------  -----",
            ]
            if not self._totp_rows:
                lines.extend(
                    ["", "No TOTP entries found.", "Use add-totp to create one."]
                )
            else:
                for row in self._totp_rows:
                    period = max(1, int(row["period"]))
                    rem = period - (now % period)
                    if rem <= 0:
                        rem = period
                    code = (
                        "******"
                        if secret_mode
                        else self._service.get_totp_code(int(row["id"]))
                    )
                    lines.append(
                        f"{row['id']:>2}  {row['source']:<3}  {rem:>3}  {str(code):<8}  {row['label']}"
                    )
                lines.extend(
                    [
                        "",
                        "source: det=deterministic, imp=imported",
                        "Commands: 2fa-copy <entry_id>, 2fa-copy-url <entry_id>, 2fa-refresh, 2fa-hide",
                    ]
                )
            self.query_one("#totp-board", Static).update("\n".join(lines))
            self._clear_failure()

        def _tick_totp_board(self) -> None:
            if self.totp_board_open:
                self._refresh_totp_board(force_reload=False)

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

        def _selected_entry_payload(self) -> dict[str, Any]:
            if self._session_locked:
                raise ValueError("Vault is locked. Run: unlock <password>")
            if self._service is None:
                raise ValueError("Entry service unavailable")
            if self._selected_entry_id is None:
                raise ValueError("No entry selected")
            entry = self._selected_entry or self._service.retrieve_entry(
                self._selected_entry_id
            )
            if not isinstance(entry, dict) or not entry:
                raise ValueError("Selected entry not found")
            return dict(entry)

        def _resolve_copy_field_value(self, field: str) -> tuple[str, bool, str]:
            if self._service is None:
                raise ValueError("Entry service unavailable")
            entry = self._selected_entry_payload()
            entry_id = int(self._selected_entry_id or 0)
            kind = self._entry_kind(entry)
            key = field.strip().lower()

            if kind in {"password", "stored_password"}:
                if key in {"password", "pass"}:
                    length = int(entry.get("length", 16))
                    return (
                        str(self._service.generate_password(length, entry_id)),
                        True,
                        "password",
                    )
                if key == "username":
                    return str(entry.get("username") or ""), False, "username"
                if key == "url":
                    return str(entry.get("url") or ""), False, "url"
                raise ValueError(
                    "copy field unsupported for password: password|username|url"
                )

            if kind in {"seed", "managed_account"}:
                if key not in {"seed", "phrase"}:
                    raise ValueError("copy field unsupported for seed: seed|phrase")
                getter = (
                    self._service.get_managed_account_seed
                    if kind == "managed_account"
                    else self._service.get_seed_phrase
                )
                return str(getter(entry_id)), True, "seed"

            if kind == "totp":
                if key == "code":
                    return str(self._service.get_totp_code(entry_id)), True, "code"
                if key == "secret":
                    return str(self._service.get_totp_secret(entry_id)), True, "secret"
                if key in {"url", "uri", "otpauth"}:
                    from seedpass.core.totp import TotpManager

                    secret = str(self._service.get_totp_secret(entry_id))
                    label = str(entry.get("label") or f"totp-{entry_id}")
                    period = int(entry.get("period", 30))
                    digits = int(entry.get("digits", 6))
                    uri = TotpManager.make_otpauth_uri(
                        label, secret, period=period, digits=digits
                    )
                    return uri, True, "url"
                raise ValueError("copy field unsupported for totp: code|secret|url")

            if kind == "ssh":
                private_key, public_key = self._service.get_ssh_key_pair(entry_id)
                if key in {"public", "public_key"}:
                    return str(public_key), False, "public_key"
                if key in {"private", "private_key"}:
                    return str(private_key), True, "private_key"
                raise ValueError("copy field unsupported for ssh: public|private")

            if kind == "pgp":
                private_key, public_key, fingerprint_text = self._service.get_pgp_key(
                    entry_id
                )
                if key in {"private", "private_key"}:
                    return str(private_key), True, "private_key"
                if key in {"public", "public_key"}:
                    return str(public_key), False, "public_key"
                if key in {"fingerprint", "fpr"}:
                    return str(fingerprint_text), False, "fingerprint"
                raise ValueError(
                    "copy field unsupported for pgp: private|public|fingerprint"
                )

            if kind == "nostr":
                npub, nsec = self._service.get_nostr_key_pair(entry_id)
                if key == "npub":
                    return str(npub), False, "npub"
                if key == "nsec":
                    return str(nsec), True, "nsec"
                raise ValueError("copy field unsupported for nostr: npub|nsec")

            if kind == "key_value":
                if key == "key":
                    return str(entry.get("key") or ""), False, "key"
                if key == "value":
                    return str(entry.get("value") or ""), True, "value"
                raise ValueError("copy field unsupported for key_value: key|value")

            if kind in {"document", "note"}:
                if key not in {"content", "text"}:
                    raise ValueError(
                        "copy field unsupported for document: content|text"
                    )
                return str(entry.get("content") or ""), False, "content"

            raise ValueError(f"copy not supported for kind '{kind or 'unknown'}'")

        def _export_value_to_path(self, value: str, output_path: str) -> Path:
            raw = Path(output_path).expanduser()
            if not raw.is_absolute():
                raw = Path.cwd() / raw
            raw.parent.mkdir(parents=True, exist_ok=True)
            raw.write_text(value, encoding="utf-8")
            return raw

        def _apply_selected_modify(
            self,
            *,
            raw_command: str,
            success_message: str,
            failure_context: str,
            hint: str = "Press 'x' to retry.",
            **kwargs: Any,
        ) -> None:
            if self._service is None or self._selected_entry_id is None:
                self._set_status("No entry selected")
                return
            try:
                self._service.modify_entry(self._selected_entry_id, **kwargs)
                current_id = self._selected_entry_id
                self._load_entries(self._last_query, reset_page=False)
                if current_id in self._entry_ids_in_view:
                    self._show_entry(current_id)
                self._clear_failure()
                self._set_status(success_message)
            except Exception as exc:
                self._record_failure(
                    failure_context,
                    exc,
                    retry=lambda: self._run_palette_command(raw_command),
                    hint=hint,
                )

        @staticmethod
        def _parse_toggle_token(token: str) -> bool:
            value = token.strip().lower()
            if value in {"1", "true", "yes", "y", "on", "enable", "enabled"}:
                return True
            if value in {"0", "false", "no", "n", "off", "disable", "disabled"}:
                return False
            raise ValueError(f"invalid toggle value '{token}'")

        def _run_palette_command(self, command: str) -> None:
            raw = command.strip()
            try:
                cmd, args = parse_palette_command(raw)
            except ValueError as exc:
                self._set_status(str(exc))
                return

            if cmd == "help":
                self.query_one("#entry-detail", Static).update(
                    self._palette_reference_text()
                )
                self._set_status(self._palette_help_summary())
                return
            if cmd in {"help-commands", "commands"}:
                if args:
                    self._set_status("Usage: help-commands")
                    return
                self.query_one("#entry-detail", Static).update(
                    self._palette_reference_text()
                )
                self._set_status("Displayed full palette command reference")
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

            if cmd in {"onboarding", "welcome"}:
                if args:
                    self._set_status("Usage: onboarding")
                    return
                self.query_one("#entry-detail", Static).update(self._onboarding_text())
                self._set_status("Displayed onboarding guide")
                return
            if cmd == "quickstart":
                if args:
                    self._set_status("Usage: quickstart")
                    return
                self.query_one("#entry-detail", Static).update(self._onboarding_text())
                self._set_status("Displayed quick start guide")
                return

            if cmd == "stats":
                if args:
                    self._set_status("Usage: stats")
                    return
                self.query_one("#entry-detail", Static).update(self._stats_text())
                self._set_status("Displayed vault stats")
                return

            if cmd == "settings":
                if args:
                    self._set_status("Usage: settings")
                    return
                self.action_toggle_settings()
                return

            if cmd == "maximize":
                if args:
                    self._set_status("Usage: maximize")
                    return
                self.action_maximize_inspector()
                return
            if cmd == "density":
                if len(args) != 1:
                    self._set_status("Usage: density <compact|comfortable>")
                    return
                mode = args[0].strip().lower()
                if mode not in {"compact", "comfortable"}:
                    self._set_status("density must be one of: compact, comfortable")
                    return
                self._density_mode = mode
                self._render_current_page(preserve_selected=True)
                self._update_filters_panel()
                self._set_status(f"Density set to {mode}")
                return
            if cmd == "session-status":
                if args:
                    self._set_status("Usage: session-status")
                    return
                lock_state = "locked" if self._session_locked else "unlocked"
                managed_state = (
                    f"entry #{self._managed_session_entry_id}"
                    if self._managed_session_entry_id is not None
                    else "none"
                )
                vault_state = (
                    "connected" if self._vault_service is not None else "unavailable"
                )
                self.query_one("#entry-detail", Static).update(
                    "\n".join(
                        [
                            "Session Status",
                            "--------------",
                            "",
                            f"Vault lock state: {lock_state}",
                            f"Managed account session: {managed_state}",
                            f"Vault service: {vault_state}",
                        ]
                    )
                )
                self._update_filters_panel()
                self._set_status("Displayed session status")
                return
            if cmd == "lock":
                if args:
                    self._set_status("Usage: lock")
                    return
                if self._vault_service is None:
                    self._set_status("Vault service unavailable")
                    return
                locker = getattr(self._vault_service, "lock", None)
                if not callable(locker):
                    self._set_status("Vault service does not support lock")
                    return
                try:
                    locker()
                    self._session_locked = True
                    self._clear_failure()
                    self._selected_entry_id = None
                    self._selected_entry = None
                    self._current_links = []
                    self._current_link_cursor = 0
                    self._all_results = []
                    self._result_page = 0
                    self._render_current_page(preserve_selected=False)
                    self._set_secret_panel(
                        "Vault locked. Sensitive data hidden.\nRun: unlock <password>"
                    )
                    self._update_filters_panel()
                    self._set_status("Vault locked")
                except Exception as exc:
                    self._record_failure(
                        "lock failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return
            if cmd == "unlock":
                if len(args) != 1:
                    self._set_status("Usage: unlock <password>")
                    return
                if self._vault_service is None:
                    self._set_status("Vault service unavailable")
                    return
                unlocker = getattr(self._vault_service, "unlock", None)
                if not callable(unlocker):
                    self._set_status("Vault service does not support unlock")
                    return
                try:
                    from seedpass.core.api import UnlockRequest

                    response = unlocker(UnlockRequest(password=args[0]))
                    self._session_locked = False
                    self._load_entries(self._last_query, reset_page=False)
                    self._set_secret_panel(
                        "Sensitive data hidden. Use 'v' to reveal 🔑 or 'g' for QR ▦."
                    )
                    self._clear_failure()
                    duration = getattr(response, "duration", None)
                    if isinstance(duration, (int, float)):
                        self._set_status(f"Vault unlocked in {float(duration):.2f}s")
                    else:
                        self._set_status("Vault unlocked")
                except Exception as exc:
                    self._record_failure(
                        "unlock failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "filter":
                if len(args) != 1:
                    self._set_status(
                        "Usage: filter <kind|comma-list|all|secrets|docs|keys|2fa>"
                    )
                    return
                self.filter_kind = self._normalize_filter_kind(args[0])
                self._remember_filter_for_active_profile()
                self._update_filters_panel()
                self._load_entries(query=self._last_query, reset_page=True)
                self._set_status(f"Applied filter: {self.filter_kind}")
                return

            if cmd == "archive-filter":
                if len(args) != 1:
                    self._set_status("Usage: archive-filter <active|all|archived>")
                    return
                mode = args[0].strip().lower()
                if mode not in {"active", "all", "archived"}:
                    self._set_status(
                        "archive-filter must be one of: active, all, archived"
                    )
                    return
                self.archive_scope = mode
                self._update_filters_panel()
                self._load_entries(query=self._last_query, reset_page=True)
                self._set_status(f"Applied archive filter: {self.archive_scope}")
                return

            if cmd == "add-password":
                if self._service is None:
                    self._set_status("Entry service unavailable")
                    return
                if len(args) < 2 or len(args) > 4:
                    self._set_status(
                        "Usage: add-password <label> <length> [username] [url]"
                    )
                    return
                label = args[0].strip()
                if not label:
                    self._set_status("add-password label is required")
                    return
                try:
                    length = int(args[1])
                except ValueError:
                    self._set_status("add-password length must be an integer")
                    return
                username = args[2] if len(args) >= 3 else None
                url = args[3] if len(args) >= 4 else None
                try:
                    new_id = self._service.add_entry(
                        label,
                        length,
                        username=username,
                        url=url,
                    )
                    self._load_entries(self._last_query, reset_page=False)
                    self._show_entry(int(new_id))
                    self._clear_failure()
                    self._set_status(f"Added password entry #{int(new_id)}")
                except Exception as exc:
                    self._record_failure(
                        "add-password failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "add-totp":
                if self._service is None:
                    self._set_status("Entry service unavailable")
                    return
                if len(args) < 1 or len(args) > 4:
                    self._set_status(
                        "Usage: add-totp <label> [period] [digits] [secret]"
                    )
                    return
                label = args[0].strip()
                if not label:
                    self._set_status("add-totp label is required")
                    return
                period = 30
                digits = 6
                secret: str | None = None
                if len(args) >= 2:
                    try:
                        period = int(args[1])
                    except ValueError:
                        self._set_status("add-totp period must be an integer")
                        return
                if len(args) >= 3:
                    try:
                        digits = int(args[2])
                    except ValueError:
                        self._set_status("add-totp digits must be an integer")
                        return
                if len(args) >= 4:
                    secret = args[3].strip() or None
                deterministic = secret is None
                try:
                    self._service.add_totp(
                        label,
                        period=period,
                        digits=digits,
                        deterministic=deterministic,
                        secret=secret,
                    )
                    self._load_entries(self._last_query, reset_page=False)
                    try:
                        matches = self._service.search_entries(label, kinds=["totp"])
                    except Exception:
                        matches = []
                    selected = None
                    for row in matches:
                        idx, entry_label, _u, _url, _arch, _etype = row
                        if str(entry_label) == label:
                            selected = int(idx)
                    if selected is None and matches:
                        selected = int(matches[-1][0])
                    if selected is not None:
                        self._show_entry(selected)
                        self._set_status(f"Added TOTP entry #{selected}")
                    else:
                        self._set_status("Added TOTP entry")
                    self._clear_failure()
                except Exception as exc:
                    self._record_failure(
                        "add-totp failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "add-key-value":
                if self._service is None:
                    self._set_status("Entry service unavailable")
                    return
                if len(args) != 3:
                    self._set_status("Usage: add-key-value <label> <key> <value>")
                    return
                label = args[0].strip()
                key = args[1]
                value = args[2]
                if not label:
                    self._set_status("add-key-value label is required")
                    return
                try:
                    new_id = self._service.add_key_value(label, key, value)
                    self._load_entries(self._last_query, reset_page=False)
                    self._show_entry(int(new_id))
                    self._clear_failure()
                    self._set_status(f"Added key/value entry #{int(new_id)}")
                except Exception as exc:
                    self._record_failure(
                        "add-key-value failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "add-document":
                if self._service is None:
                    self._set_status("Entry service unavailable")
                    return
                if len(args) != 3:
                    self._set_status(
                        "Usage: add-document <label> <file_type> <content>"
                    )
                    return
                label = args[0].strip()
                file_type = args[1].strip().lstrip(".") or "txt"
                content = args[2]
                if not label:
                    self._set_status("add-document label is required")
                    return
                try:
                    new_id = self._service.add_document(
                        label,
                        content,
                        file_type=file_type,
                    )
                    self._load_entries(self._last_query, reset_page=False)
                    self._show_entry(int(new_id))
                    self._clear_failure()
                    self._set_status(f"Added document entry #{int(new_id)}")
                except Exception as exc:
                    self._record_failure(
                        "add-document failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "add-ssh":
                if self._service is None:
                    self._set_status("Entry service unavailable")
                    return
                if len(args) < 1 or len(args) > 2:
                    self._set_status("Usage: add-ssh <label> [index]")
                    return
                label = args[0].strip()
                if not label:
                    self._set_status("add-ssh label is required")
                    return
                index = None
                if len(args) == 2:
                    try:
                        index = int(args[1])
                    except ValueError:
                        self._set_status("add-ssh index must be an integer")
                        return
                try:
                    new_id = self._service.add_ssh_key(label, index=index)
                    self._load_entries(self._last_query, reset_page=False)
                    self._show_entry(int(new_id))
                    self._clear_failure()
                    self._set_status(f"Added SSH entry #{int(new_id)}")
                except Exception as exc:
                    self._record_failure(
                        "add-ssh failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "add-pgp":
                if self._service is None:
                    self._set_status("Entry service unavailable")
                    return
                if len(args) < 1 or len(args) > 4:
                    self._set_status(
                        "Usage: add-pgp <label> [index] [key_type] [user_id]"
                    )
                    return
                label = args[0].strip()
                if not label:
                    self._set_status("add-pgp label is required")
                    return
                index = None
                key_type = "ed25519"
                user_id = ""
                if len(args) >= 2:
                    try:
                        index = int(args[1])
                    except ValueError:
                        self._set_status("add-pgp index must be an integer")
                        return
                if len(args) >= 3:
                    key_type = args[2].strip() or "ed25519"
                if len(args) >= 4:
                    user_id = args[3]
                try:
                    new_id = self._service.add_pgp_key(
                        label,
                        index=index,
                        key_type=key_type,
                        user_id=user_id,
                    )
                    self._load_entries(self._last_query, reset_page=False)
                    self._show_entry(int(new_id))
                    self._clear_failure()
                    self._set_status(f"Added PGP entry #{int(new_id)}")
                except Exception as exc:
                    self._record_failure(
                        "add-pgp failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "add-nostr":
                if self._service is None:
                    self._set_status("Entry service unavailable")
                    return
                if len(args) < 1 or len(args) > 2:
                    self._set_status("Usage: add-nostr <label> [index]")
                    return
                label = args[0].strip()
                if not label:
                    self._set_status("add-nostr label is required")
                    return
                index = None
                if len(args) == 2:
                    try:
                        index = int(args[1])
                    except ValueError:
                        self._set_status("add-nostr index must be an integer")
                        return
                try:
                    new_id = self._service.add_nostr_key(label, index=index)
                    self._load_entries(self._last_query, reset_page=False)
                    self._show_entry(int(new_id))
                    self._clear_failure()
                    self._set_status(f"Added Nostr entry #{int(new_id)}")
                except Exception as exc:
                    self._record_failure(
                        "add-nostr failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "add-seed":
                if self._service is None:
                    self._set_status("Entry service unavailable")
                    return
                if len(args) < 1 or len(args) > 3:
                    self._set_status("Usage: add-seed <label> [words] [index]")
                    return
                label = args[0].strip()
                if not label:
                    self._set_status("add-seed label is required")
                    return
                words = 24
                index = None
                if len(args) >= 2:
                    try:
                        words = int(args[1])
                    except ValueError:
                        self._set_status("add-seed words must be an integer")
                        return
                if len(args) == 3:
                    try:
                        index = int(args[2])
                    except ValueError:
                        self._set_status("add-seed index must be an integer")
                        return
                try:
                    new_id = self._service.add_seed(
                        label,
                        words=words,
                        index=index,
                    )
                    self._load_entries(self._last_query, reset_page=False)
                    self._show_entry(int(new_id))
                    self._clear_failure()
                    self._set_status(f"Added seed entry #{int(new_id)}")
                except Exception as exc:
                    self._record_failure(
                        "add-seed failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd in ("add-managed-account", "add-managed"):
                if self._service is None:
                    self._set_status("Entry service unavailable")
                    return
                if len(args) < 1 or len(args) > 2:
                    self._set_status("Usage: add-managed-account <label> [index]")
                    return
                label = args[0].strip()
                if not label:
                    self._set_status("add-managed-account label is required")
                    return
                index = None
                if len(args) == 2:
                    try:
                        index = int(args[1])
                    except ValueError:
                        self._set_status("add-managed-account index must be an integer")
                        return
                try:
                    new_id = self._service.add_managed_account(label, index=index)
                    self._load_entries(self._last_query, reset_page=False)
                    self._show_entry(int(new_id))
                    self._clear_failure()
                    self._set_status(f"Added managed account entry #{int(new_id)}")
                except Exception as exc:
                    self._record_failure(
                        "add-managed-account failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "notes-set":
                if not args:
                    self._set_status("Usage: notes-set <text>")
                    return
                notes_text = " ".join(args).strip()
                if not notes_text:
                    self._set_status("notes-set text is required")
                    return
                self._apply_selected_modify(
                    raw_command=raw,
                    success_message="Updated notes for selected entry",
                    failure_context="notes-set failed",
                    notes=notes_text,
                )
                return

            if cmd == "notes-clear":
                if args:
                    self._set_status("Usage: notes-clear")
                    return
                self._apply_selected_modify(
                    raw_command=raw,
                    success_message="Cleared notes for selected entry",
                    failure_context="notes-clear failed",
                    notes="",
                )
                return

            if cmd == "tag-add":
                if len(args) != 1:
                    self._set_status("Usage: tag-add <tag>")
                    return
                tag = args[0].strip()
                if not tag:
                    self._set_status("tag-add tag is required")
                    return
                try:
                    entry = self._selected_entry_payload()
                except Exception as exc:
                    self._set_status(str(exc))
                    return
                current_tags = entry.get("tags")
                tags = (
                    [str(item).strip() for item in current_tags if str(item).strip()]
                    if isinstance(current_tags, list)
                    else []
                )
                if tag not in tags:
                    tags.append(tag)
                self._apply_selected_modify(
                    raw_command=raw,
                    success_message=f"Added tag '{tag}'",
                    failure_context="tag-add failed",
                    tags=tags,
                )
                return

            if cmd == "tag-rm":
                if len(args) != 1:
                    self._set_status("Usage: tag-rm <tag>")
                    return
                tag = args[0].strip()
                if not tag:
                    self._set_status("tag-rm tag is required")
                    return
                try:
                    entry = self._selected_entry_payload()
                except Exception as exc:
                    self._set_status(str(exc))
                    return
                current_tags = entry.get("tags")
                tags = (
                    [str(item).strip() for item in current_tags if str(item).strip()]
                    if isinstance(current_tags, list)
                    else []
                )
                next_tags = [item for item in tags if item != tag]
                self._apply_selected_modify(
                    raw_command=raw,
                    success_message=f"Removed tag '{tag}'",
                    failure_context="tag-rm failed",
                    tags=next_tags,
                )
                return

            if cmd == "tags-set":
                if not args:
                    self._set_status("Usage: tags-set <comma-separated tags>")
                    return
                raw_tags = " ".join(args).strip()
                tags = [item.strip() for item in raw_tags.split(",") if item.strip()]
                self._apply_selected_modify(
                    raw_command=raw,
                    success_message="Updated tags for selected entry",
                    failure_context="tags-set failed",
                    tags=tags,
                )
                return

            if cmd == "tags-clear":
                if args:
                    self._set_status("Usage: tags-clear")
                    return
                self._apply_selected_modify(
                    raw_command=raw,
                    success_message="Cleared tags for selected entry",
                    failure_context="tags-clear failed",
                    tags=[],
                )
                return

            if cmd == "field-add":
                if len(args) < 2 or len(args) > 3:
                    self._set_status(
                        "Usage: field-add <label> <value> (optional: hidden)"
                    )
                    return
                field_label = args[0].strip()
                field_value = args[1]
                if not field_label:
                    self._set_status("field-add label is required")
                    return
                hidden = False
                if len(args) == 3:
                    token = args[2].strip().lower()
                    hidden = token in {"hidden", "1", "true", "yes", "y"}
                try:
                    entry = self._selected_entry_payload()
                except Exception as exc:
                    self._set_status(str(exc))
                    return
                current_fields = entry.get("custom_fields")
                fields = (
                    [dict(item) for item in current_fields if isinstance(item, dict)]
                    if isinstance(current_fields, list)
                    else []
                )
                fields.append(
                    {"label": field_label, "value": field_value, "is_hidden": hidden}
                )
                self._apply_selected_modify(
                    raw_command=raw,
                    success_message=f"Added custom field '{field_label}'",
                    failure_context="field-add failed",
                    custom_fields=fields,
                )
                return

            if cmd == "field-rm":
                if len(args) != 1:
                    self._set_status("Usage: field-rm <label>")
                    return
                field_label = args[0].strip()
                if not field_label:
                    self._set_status("field-rm label is required")
                    return
                try:
                    entry = self._selected_entry_payload()
                except Exception as exc:
                    self._set_status(str(exc))
                    return
                current_fields = entry.get("custom_fields")
                fields = (
                    [dict(item) for item in current_fields if isinstance(item, dict)]
                    if isinstance(current_fields, list)
                    else []
                )
                normalized = field_label.lower()
                next_fields = [
                    item
                    for item in fields
                    if str(item.get("label", "")).strip().lower() != normalized
                ]
                self._apply_selected_modify(
                    raw_command=raw,
                    success_message=f"Removed custom field '{field_label}'",
                    failure_context="field-rm failed",
                    custom_fields=next_fields,
                )
                return

            if cmd in {"set-field", "field-set"}:
                if len(args) < 2:
                    self._set_status("Usage: set-field <name> <value>")
                    return
                field_raw = args[0].strip().lower()
                field = field_raw.replace("-", "_")
                value_raw = " ".join(args[1:]).strip()
                if not field:
                    self._set_status("set-field name is required")
                    return
                if not value_raw:
                    self._set_status("set-field value is required")
                    return
                alias = {
                    "name": "label",
                    "user": "username",
                    "pass_length": "length",
                    "filetype": "file_type",
                }
                field = alias.get(field, field)
                try:
                    entry = self._selected_entry_payload()
                except Exception as exc:
                    self._set_status(str(exc))
                    return
                kind = str(entry.get("kind") or entry.get("type") or "").lower()
                allowed_fields = {
                    "password": {"label", "notes", "username", "url", "length"},
                    "totp": {"label", "notes", "period", "digits"},
                    "key_value": {"label", "notes", "key", "value"},
                    "document": {"label", "notes", "file_type", "content"},
                    "ssh": {"label", "notes"},
                    "pgp": {"label", "notes"},
                    "nostr": {"label", "notes"},
                    "seed": {"label", "notes"},
                    "managed_account": {"label", "notes"},
                }
                allowed = allowed_fields.get(kind, {"label", "notes"})
                if field not in allowed:
                    self._set_status(
                        f"set-field '{field}' not supported for kind '{kind or 'unknown'}'"
                    )
                    return
                value: Any = value_raw
                if field in {"length", "period", "digits"}:
                    try:
                        value = int(value_raw)
                    except ValueError:
                        self._set_status(f"set-field {field} must be an integer")
                        return
                if field == "file_type":
                    value = str(value).strip().lstrip(".") or "txt"
                self._apply_selected_modify(
                    raw_command=raw,
                    success_message=f"Updated {field} for selected entry",
                    failure_context="set-field failed",
                    **{field: value},
                )
                return

            if cmd in {"clear-field", "field-clear"}:
                if len(args) != 1:
                    self._set_status("Usage: clear-field <name>")
                    return
                field_raw = args[0].strip().lower()
                field = field_raw.replace("-", "_")
                if not field:
                    self._set_status("clear-field name is required")
                    return
                alias = {
                    "user": "username",
                    "filetype": "file_type",
                }
                field = alias.get(field, field)
                try:
                    entry = self._selected_entry_payload()
                except Exception as exc:
                    self._set_status(str(exc))
                    return
                kind = str(entry.get("kind") or entry.get("type") or "").lower()
                clearable = {
                    "password": {"username", "url", "notes"},
                    "totp": {"notes"},
                    "key_value": {"notes", "key", "value"},
                    "document": {"notes", "content"},
                    "ssh": {"notes"},
                    "pgp": {"notes"},
                    "nostr": {"notes"},
                    "seed": {"notes"},
                    "managed_account": {"notes"},
                }
                allowed = clearable.get(kind, {"notes"})
                if field not in allowed:
                    self._set_status(
                        f"clear-field '{field}' not supported for kind '{kind or 'unknown'}'"
                    )
                    return
                self._apply_selected_modify(
                    raw_command=raw,
                    success_message=f"Cleared {field} for selected entry",
                    failure_context="clear-field failed",
                    **{field: ""},
                )
                return

            if cmd == "2fa-board":
                if args:
                    self._set_status("Usage: 2fa-board")
                    return
                self._set_totp_board_visible(True)
                self._set_status("2FA board opened")
                return

            if cmd == "2fa-hide":
                if args:
                    self._set_status("Usage: 2fa-hide")
                    return
                self._set_totp_board_visible(False)
                self._set_status("2FA board closed")
                return

            if cmd == "2fa-refresh":
                if args:
                    self._set_status("Usage: 2fa-refresh")
                    return
                self._refresh_totp_board(force_reload=True)
                self._set_status("2FA board refreshed")
                return

            if cmd == "2fa-copy":
                if len(args) != 1:
                    self._set_status("Usage: 2fa-copy <entry_id>")
                    return
                if self._service is None:
                    self._set_status("Entry service unavailable")
                    return
                try:
                    entry_id = int(args[0])
                except ValueError:
                    self._set_status("2fa-copy entry_id must be an integer")
                    return
                try:
                    code = self._service.get_totp_code(entry_id)
                except Exception as exc:
                    self._record_failure(
                        "2fa-copy failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                    return
                if not self._copy_to_clipboard(code):
                    self._set_status("Clipboard copy unavailable")
                    return
                delay = self._clipboard_clear_delay()
                if self.totp_board_open:
                    self._refresh_totp_board(force_reload=False)
                self._set_status(
                    f"Copied TOTP code for entry {entry_id} to clipboard ({delay}s clear)"
                )
                self._clear_failure()
                return

            if cmd == "2fa-copy-url":
                if len(args) != 1:
                    self._set_status("Usage: 2fa-copy-url <entry_id>")
                    return
                if self._service is None:
                    self._set_status("Entry service unavailable")
                    return
                try:
                    entry_id = int(args[0])
                except ValueError:
                    self._set_status("2fa-copy-url entry_id must be an integer")
                    return
                try:
                    entry = self._service.retrieve_entry(entry_id)
                    if not isinstance(entry, dict) or not entry:
                        self._set_status(f"Entry {entry_id} not found")
                        return
                    kind = str(entry.get("kind") or entry.get("type") or "").lower()
                    if kind != "totp":
                        self._set_status("2fa-copy-url requires a TOTP entry")
                        return
                    from seedpass.core.totp import TotpManager

                    secret = str(self._service.get_totp_secret(entry_id))
                    label = str(entry.get("label") or f"totp-{entry_id}")
                    period = int(entry.get("period", 30))
                    digits = int(entry.get("digits", 6))
                    uri = TotpManager.make_otpauth_uri(
                        label, secret, period=period, digits=digits
                    )
                except Exception as exc:
                    self._record_failure(
                        "2fa-copy-url failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                    return
                if not self._copy_to_clipboard(uri):
                    self._set_status("Clipboard copy unavailable")
                    return
                delay = self._clipboard_clear_delay()
                self._set_status(
                    f"Copied TOTP URL for entry {entry_id} to clipboard ({delay}s clear)"
                )
                self._clear_failure()
                return

            if cmd == "profiles-list":
                if args:
                    self._set_status("Usage: profiles-list")
                    return
                if self._profile_service is None:
                    self._set_status("Profile service unavailable")
                    return
                try:
                    rows = self._profile_service.list_profiles()
                    profiles = [str(item) for item in rows]
                    if profiles:
                        self._set_status(
                            f"Profiles ({len(profiles)}): " + ", ".join(profiles[:4])
                        )
                    else:
                        self._set_status("No profiles found")
                    self._clear_failure()
                except Exception as exc:
                    self._record_failure(
                        "profiles-list failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "profile-switch":
                if self._profile_service is None:
                    self._set_status("Profile service unavailable")
                    return
                if len(args) < 1 or len(args) > 2:
                    self._set_status(
                        "Usage: profile-switch <fingerprint> (optional: password)"
                    )
                    return
                fp = args[0].strip()
                if not fp:
                    self._set_status("profile-switch fingerprint is required")
                    return
                password = args[1] if len(args) == 2 else None
                try:
                    from seedpass.core.api import ProfileSwitchRequest

                    self._remember_sidebar_for_active_profile()
                    self._profile_service.switch_profile(
                        ProfileSwitchRequest(fingerprint=fp, password=password)
                    )
                    self._active_profile_fp = fp
                    self._root_profile_fp = self._active_profile_key()
                    self._profile_tree_expanded[fp] = True
                    self._managed_session_stack = []
                    self._managed_session_entry_id = None
                    self._restore_filter_for_active_profile(default_filter="all")
                    self._restore_sidebar_for_active_profile(default_collapsed=False)
                    self._clear_failure()
                    self._load_entries(self._last_query, reset_page=True)
                    self._refresh_profile_tree()
                    self._set_status(f"Switched profile to {fp}")
                except Exception as exc:
                    self._record_failure(
                        "profile-switch failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "profile-add":
                if self._profile_service is None:
                    self._set_status("Profile service unavailable")
                    return
                if args:
                    self._set_status("Usage: profile-add")
                    return
                try:
                    fp = self._profile_service.add_profile()
                    self._clear_failure()
                    self._refresh_profile_tree()
                    if fp:
                        self._set_status(f"Created profile {fp}")
                    else:
                        self._set_status("Created profile")
                except Exception as exc:
                    self._record_failure(
                        "profile-add failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "profile-remove":
                if self._profile_service is None:
                    self._set_status("Profile service unavailable")
                    return
                if len(args) != 1:
                    self._set_status("Usage: profile-remove <fingerprint>")
                    return
                fp = args[0].strip()
                if not fp:
                    self._set_status("profile-remove fingerprint is required")
                    return
                try:
                    from seedpass.core.api import ProfileRemoveRequest

                    self._profile_service.remove_profile(
                        ProfileRemoveRequest(fingerprint=fp)
                    )
                    self._clear_failure()
                    self._refresh_profile_tree()
                    self._set_status(f"Removed profile {fp}")
                except Exception as exc:
                    self._record_failure(
                        "profile-remove failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "profile-rename":
                if self._profile_service is None:
                    self._set_status("Profile service unavailable")
                    return
                if len(args) < 2:
                    self._set_status("Usage: profile-rename <fingerprint> <name>")
                    return
                fp = args[0].strip()
                name = " ".join(args[1:]).strip()
                if not fp:
                    self._set_status("profile-rename fingerprint is required")
                    return
                if not name:
                    self._set_status("profile-rename name is required")
                    return
                try:
                    self._profile_service.rename_profile(fp, name)
                    self._clear_failure()
                    self._refresh_profile_tree()
                    self._set_status(f"Renamed profile {fp} to '{name}'")
                except Exception as exc:
                    self._record_failure(
                        "profile-rename failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "profile-tree-next":
                if args:
                    self._set_status("Usage: profile-tree-next")
                    return
                self.action_profile_tree_next()
                return

            if cmd == "profile-tree-prev":
                if args:
                    self._set_status("Usage: profile-tree-prev")
                    return
                self.action_profile_tree_prev()
                return

            if cmd == "profile-tree-open":
                if args:
                    self._set_status("Usage: profile-tree-open")
                    return
                self.action_profile_tree_open()
                return

            if cmd == "profile-tree-toggle":
                if args:
                    self._set_status("Usage: profile-tree-toggle")
                    return
                self.action_profile_tree_toggle()
                return

            if cmd == "setting-secret":
                if self._config_service is None:
                    self._set_status("Config service unavailable")
                    return
                if len(args) < 1 or len(args) > 2:
                    self._set_status("Usage: setting-secret <on|off> [delay]")
                    return
                try:
                    enabled = self._parse_toggle_token(args[0])
                except ValueError as exc:
                    self._set_status(str(exc))
                    return
                delay = self._clipboard_clear_delay()
                if len(args) == 2:
                    try:
                        delay = int(args[1])
                    except ValueError:
                        self._set_status("setting-secret delay must be an integer")
                        return
                setter = getattr(self._config_service, "set_secret_mode", None)
                if not callable(setter):
                    self._set_status("Config service does not support secret mode")
                    return
                try:
                    setter(enabled, int(delay))
                    self._clear_failure()
                    state = "on" if enabled else "off"
                    self._set_status(f"Secret mode {state} (delay {int(delay)}s)")
                    if self.totp_board_open:
                        self._refresh_totp_board(force_reload=False)
                except Exception as exc:
                    self._record_failure(
                        "setting-secret failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "setting-offline":
                if self._config_service is None:
                    self._set_status("Config service unavailable")
                    return
                if len(args) != 1:
                    self._set_status("Usage: setting-offline <on|off>")
                    return
                try:
                    enabled = self._parse_toggle_token(args[0])
                except ValueError as exc:
                    self._set_status(str(exc))
                    return
                setter = getattr(self._config_service, "set_offline_mode", None)
                if not callable(setter):
                    self._set_status("Config service does not support offline mode")
                    return
                try:
                    setter(enabled)
                    self._clear_failure()
                    self._set_status(f"Offline mode {'on' if enabled else 'off'}")
                except Exception as exc:
                    self._record_failure(
                        "setting-offline failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "setting-quick-unlock":
                if self._config_service is None:
                    self._set_status("Config service unavailable")
                    return
                if len(args) != 1:
                    self._set_status("Usage: setting-quick-unlock <on|off>")
                    return
                try:
                    enabled = self._parse_toggle_token(args[0])
                except ValueError as exc:
                    self._set_status(str(exc))
                    return
                setter = getattr(self._config_service, "set", None)
                if not callable(setter):
                    self._set_status("Config service does not support quick unlock")
                    return
                try:
                    setter("quick_unlock", "true" if enabled else "false")
                    self._clear_failure()
                    self._set_status(f"Quick unlock {'on' if enabled else 'off'}")
                except Exception as exc:
                    self._record_failure(
                        "setting-quick-unlock failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "setting-timeout":
                if self._config_service is None:
                    self._set_status("Config service unavailable")
                    return
                if len(args) != 1:
                    self._set_status("Usage: setting-timeout <seconds>")
                    return
                try:
                    value = float(args[0])
                except ValueError:
                    self._set_status("setting-timeout requires numeric seconds")
                    return
                setter = getattr(self._config_service, "set", None)
                if not callable(setter):
                    self._set_status("Config service does not support timeout setting")
                    return
                try:
                    setter("inactivity_timeout", str(value))
                    self._clear_failure()
                    self._set_status(f"Inactivity timeout set to {value}s")
                except Exception as exc:
                    self._record_failure(
                        "setting-timeout failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "setting-kdf-iterations":
                if self._config_service is None:
                    self._set_status("Config service unavailable")
                    return
                if len(args) != 1:
                    self._set_status("Usage: setting-kdf-iterations <n>")
                    return
                try:
                    value = int(args[0])
                except ValueError:
                    self._set_status("setting-kdf-iterations requires integer value")
                    return
                setter = getattr(self._config_service, "set", None)
                if not callable(setter):
                    self._set_status("Config service does not support KDF settings")
                    return
                try:
                    setter("kdf_iterations", str(value))
                    self._clear_failure()
                    self._set_status(f"KDF iterations set to {value}")
                except Exception as exc:
                    self._record_failure(
                        "setting-kdf-iterations failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "setting-kdf-mode":
                if self._config_service is None:
                    self._set_status("Config service unavailable")
                    return
                if len(args) != 1:
                    self._set_status("Usage: setting-kdf-mode <mode>")
                    return
                mode = args[0].strip()
                if not mode:
                    self._set_status("setting-kdf-mode mode is required")
                    return
                setter = getattr(self._config_service, "set", None)
                if not callable(setter):
                    self._set_status("Config service does not support KDF settings")
                    return
                try:
                    setter("kdf_mode", mode)
                    self._clear_failure()
                    self._set_status(f"KDF mode set to {mode}")
                except Exception as exc:
                    self._record_failure(
                        "setting-kdf-mode failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "semantic-status":
                if self._semantic_service is None:
                    self._set_status("Semantic service unavailable")
                    return
                if args:
                    self._set_status("Usage: semantic-status")
                    return
                status = getattr(self._semantic_service, "status", None)
                if not callable(status):
                    self._set_status("Semantic service does not support status")
                    return
                try:
                    payload = status() or {}
                    self._refresh_semantic_state()
                    self._update_top_ribbon()
                    self.query_one("#entry-detail", Static).update(
                        "Semantic Index Status\n---------------------\n\n"
                        + json.dumps(payload, indent=2, sort_keys=True)
                    )
                    self._clear_failure()
                    self._set_status("Displayed semantic index status")
                except Exception as exc:
                    self._record_failure(
                        "semantic-status failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "search-mode":
                if self._semantic_service is None:
                    self._set_status("Semantic service unavailable")
                    return
                if len(args) != 1:
                    self._set_status("Usage: search-mode <keyword|hybrid|semantic>")
                    return
                mode = args[0].strip().lower()
                if mode not in {"keyword", "hybrid", "semantic"}:
                    self._set_status(
                        "search-mode must be one of: keyword, hybrid, semantic"
                    )
                    return
                setter = getattr(self._semantic_service, "set_mode", None)
                if not callable(setter):
                    self._set_status("Semantic service does not support search mode")
                    return
                try:
                    setter(mode)
                    self._refresh_semantic_state()
                    self._update_top_ribbon()
                    self._update_grid_heading()
                    self._clear_failure()
                    self._set_status(f"Search mode set to {mode}")
                except Exception as exc:
                    self._record_failure(
                        "search-mode failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd in {"semantic-enable", "semantic-disable"}:
                if self._semantic_service is None:
                    self._set_status("Semantic service unavailable")
                    return
                if args:
                    self._set_status(f"Usage: {cmd}")
                    return
                setter = getattr(self._semantic_service, "set_enabled", None)
                if not callable(setter):
                    self._set_status("Semantic service does not support enable/disable")
                    return
                try:
                    enabled = cmd == "semantic-enable"
                    payload = setter(enabled) or {}
                    self._refresh_semantic_state()
                    self._update_top_ribbon()
                    self._clear_failure()
                    self._set_status(
                        "Semantic index "
                        + ("enabled" if enabled else "disabled")
                        + f" (records={int(payload.get('records', 0))})"
                    )
                except Exception as exc:
                    self._record_failure(
                        f"{cmd} failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd in {"semantic-build", "semantic-rebuild"}:
                if self._semantic_service is None:
                    self._set_status("Semantic service unavailable")
                    return
                if args:
                    self._set_status(f"Usage: {cmd}")
                    return
                runner = getattr(
                    self._semantic_service,
                    "rebuild" if cmd == "semantic-rebuild" else "build",
                    None,
                )
                if not callable(runner):
                    self._set_status("Semantic service does not support build/rebuild")
                    return
                try:
                    payload = runner() or {}
                    self._refresh_semantic_state()
                    self._update_top_ribbon()
                    self._clear_failure()
                    verb = "rebuilt" if cmd == "semantic-rebuild" else "built"
                    self._set_status(
                        f"Semantic index {verb} (records={int(payload.get('records', 0))})"
                    )
                except Exception as exc:
                    self._record_failure(
                        f"{cmd} failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "semantic-search":
                if self._semantic_service is None:
                    self._set_status("Semantic service unavailable")
                    return
                if not args:
                    self._set_status("Usage: semantic-search <query>")
                    return
                searcher = getattr(self._semantic_service, "search", None)
                if not callable(searcher):
                    self._set_status("Semantic service does not support search")
                    return
                query = " ".join(args).strip()
                if not query:
                    self._set_status("Usage: semantic-search <query>")
                    return
                try:
                    results = list(
                        searcher(query, k=10, kind=None, mode=self._semantic_mode) or []
                    )
                    self._refresh_semantic_state()
                    self._update_top_ribbon()
                    lines = [
                        f"Semantic Search: {query}",
                        "---------------------------",
                        "",
                    ]
                    if not results:
                        lines.append("No semantic matches.")
                    else:
                        for row in results[:10]:
                            entry_id = int(row.get("entry_id", 0))
                            kind = str(row.get("kind", ""))
                            label = str(row.get("label", ""))
                            score = float(row.get("score", 0.0))
                            excerpt = str(row.get("excerpt", ""))
                            lines.append(
                                f"- #{entry_id} [{kind}] {label} (score={score:.3f})"
                            )
                            if excerpt:
                                short = (
                                    excerpt
                                    if len(excerpt) <= 120
                                    else excerpt[:117] + "..."
                                )
                                lines.append(f"  {short}")
                    self.query_one("#entry-detail", Static).update("\n".join(lines))
                    self._clear_failure()
                    self._set_status(f"Semantic matches: {len(results)} for '{query}'")
                except Exception as exc:
                    self._record_failure(
                        "semantic-search failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "relay-list":
                if self._nostr_service is None:
                    self._set_status("Nostr service unavailable")
                    return
                if args:
                    self._set_status("Usage: relay-list")
                    return
                try:
                    relays = [str(item) for item in self._nostr_service.list_relays()]
                    self._clear_failure()
                    if relays:
                        self._set_status(
                            f"Relays ({len(relays)}): " + ", ".join(relays[:3])
                        )
                    else:
                        self._set_status("No relays configured")
                except Exception as exc:
                    self._record_failure(
                        "relay-list failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "relay-add":
                if self._nostr_service is None:
                    self._set_status("Nostr service unavailable")
                    return
                if len(args) != 1:
                    self._set_status("Usage: relay-add <url>")
                    return
                url = args[0].strip()
                if not url:
                    self._set_status("relay-add url is required")
                    return
                try:
                    self._nostr_service.add_relay(url)
                    self._clear_failure()
                    self._set_status(f"Added relay {url}")
                except Exception as exc:
                    self._record_failure(
                        "relay-add failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd in {"npub", "nostr-pubkey"}:
                if self._nostr_service is None:
                    self._set_status("Nostr service unavailable")
                    return
                if args:
                    self._set_status("Usage: npub")
                    return
                getter = getattr(self._nostr_service, "get_pubkey", None)
                if not callable(getter):
                    self._set_status("Nostr service does not support pubkey display")
                    return
                try:
                    pubkey = str(getter()).strip()
                    if not pubkey:
                        self._set_status("No active Nostr pubkey available")
                        return
                    panel = f"Active Nostr pubkey\n\nnpub: {pubkey}"
                    try:
                        panel = (
                            f"{panel}\n\nQR (nostr:npub)\n\n"
                            f"{render_qr_ascii(f'nostr:{pubkey}')}"
                        )
                    except Exception:
                        pass
                    self._set_secret_panel(panel)
                    self._clear_failure()
                    self._set_status("Displayed active Nostr pubkey")
                except Exception as exc:
                    self._record_failure(
                        "npub failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd in {"relay-rm", "relay-remove"}:
                if self._nostr_service is None:
                    self._set_status("Nostr service unavailable")
                    return
                if len(args) != 1:
                    self._set_status("Usage: relay-rm <index>")
                    return
                try:
                    idx = int(args[0])
                except ValueError:
                    self._set_status("relay-rm index must be an integer")
                    return
                try:
                    self._nostr_service.remove_relay(idx)
                    self._clear_failure()
                    self._set_status(f"Removed relay #{idx}")
                except Exception as exc:
                    self._record_failure(
                        "relay-rm failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "relay-reset":
                if self._nostr_service is None:
                    self._set_status("Nostr service unavailable")
                    return
                if args:
                    self._set_status("Usage: relay-reset")
                    return
                resetter = getattr(self._nostr_service, "reset_relays", None)
                if not callable(resetter):
                    self._set_status("Nostr service does not support relay reset")
                    return
                try:
                    relays = list(resetter())
                    self._clear_failure()
                    self._set_status(f"Relays reset ({len(relays)})")
                except Exception as exc:
                    self._record_failure(
                        "relay-reset failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "nostr-reset-sync-state":
                if self._nostr_service is None:
                    self._set_status("Nostr service unavailable")
                    return
                if args:
                    self._set_status("Usage: nostr-reset-sync-state")
                    return
                reset_sync = getattr(self._nostr_service, "reset_sync_state", None)
                if not callable(reset_sync):
                    self._set_status("Nostr service does not support sync-state reset")
                    return
                try:
                    current_idx = int(reset_sync())
                    self._clear_failure()
                    self._set_status(
                        f"Nostr sync state reset (account index {current_idx})"
                    )
                except Exception as exc:
                    self._record_failure(
                        "nostr-reset-sync-state failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "nostr-fresh-namespace":
                if self._nostr_service is None:
                    self._set_status("Nostr service unavailable")
                    return
                if args:
                    self._set_status("Usage: nostr-fresh-namespace")
                    return
                fresh_ns = getattr(self._nostr_service, "start_fresh_namespace", None)
                if not callable(fresh_ns):
                    self._set_status(
                        "Nostr service does not support fresh namespace rotation"
                    )
                    return
                try:
                    next_idx = int(fresh_ns())
                    self._clear_failure()
                    self._set_status(
                        f"Started fresh Nostr namespace at account index {next_idx}"
                    )
                except Exception as exc:
                    self._record_failure(
                        "nostr-fresh-namespace failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "sync-now":
                if self._sync_service is None:
                    self._set_status("Sync service unavailable")
                    return
                if args:
                    self._set_status("Usage: sync-now")
                    return
                try:
                    result = self._sync_service.sync()
                    self._clear_failure()
                    if result is None:
                        self._last_sync_text = "completed (no publish result)"
                        self._set_status("Sync completed (no publish result)")
                    else:
                        manifest = getattr(result, "manifest_id", "unknown")
                        self._last_sync_text = f"manifest {manifest}"
                        self._set_status(f"Sync completed manifest {manifest}")
                except Exception as exc:
                    self._record_failure(
                        "sync-now failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "sync-bg":
                if self._sync_service is None:
                    self._set_status("Sync service unavailable")
                    return
                if args:
                    self._set_status("Usage: sync-bg")
                    return
                try:
                    self._sync_service.start_background_vault_sync()
                    self._clear_failure()
                    self._last_sync_text = "background started"
                    self._set_status("Background sync started")
                except Exception as exc:
                    self._record_failure(
                        "sync-bg failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "checksum-verify":
                if self._utility_service is None:
                    self._set_status("Utility service unavailable")
                    return
                if args:
                    self._set_status("Usage: checksum-verify")
                    return
                verifier = getattr(self._utility_service, "verify_checksum", None)
                if not callable(verifier):
                    self._set_status("Utility service does not support checksum verify")
                    return
                try:
                    verifier()
                    self._clear_failure()
                    self._set_status("Checksum verification complete")
                except Exception as exc:
                    self._record_failure(
                        "checksum-verify failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "checksum-update":
                if self._utility_service is None:
                    self._set_status("Utility service unavailable")
                    return
                if args:
                    self._set_status("Usage: checksum-update")
                    return
                updater = getattr(self._utility_service, "update_checksum", None)
                if not callable(updater):
                    self._set_status("Utility service does not support checksum update")
                    return
                try:
                    updater()
                    self._clear_failure()
                    self._set_status("Checksum updated")
                except Exception as exc:
                    self._record_failure(
                        "checksum-update failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "db-export":
                if self._vault_service is None:
                    self._set_status("Vault service unavailable")
                    return
                if len(args) != 1:
                    self._set_status("Usage: db-export <path>")
                    return
                try:
                    from seedpass.core.api import VaultExportRequest

                    path = Path(args[0]).expanduser()
                    self._vault_service.export_vault(VaultExportRequest(path=path))
                    self._clear_failure()
                    self._set_status(f"Database exported to {path}")
                except Exception as exc:
                    self._record_failure(
                        "db-export failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "db-import":
                if self._vault_service is None:
                    self._set_status("Vault service unavailable")
                    return
                if len(args) != 1:
                    self._set_status("Usage: db-import <path>")
                    return
                try:
                    from seedpass.core.api import VaultImportRequest

                    path = Path(args[0]).expanduser()
                    self._vault_service.import_vault(VaultImportRequest(path=path))
                    self._clear_failure()
                    self._load_entries(self._last_query, reset_page=True)
                    self._set_status(f"Database imported from {path}")
                except Exception as exc:
                    self._record_failure(
                        "db-import failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "totp-export":
                if self._service is None:
                    self._set_status("Entry service unavailable")
                    return
                if len(args) != 1:
                    self._set_status("Usage: totp-export <path>")
                    return
                path = Path(args[0]).expanduser()
                try:
                    payload = self._service.export_totp_entries()
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(
                        json.dumps(payload, indent=2, sort_keys=True),
                        encoding="utf-8",
                    )
                    self._clear_failure()
                    self._set_status(f"Exported TOTP entries to {path}")
                except Exception as exc:
                    self._record_failure(
                        "totp-export failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "parent-seed-backup":
                if self._vault_service is None:
                    self._set_status("Vault service unavailable")
                    return
                if len(args) > 2:
                    self._set_status(
                        "Usage: parent-seed-backup (optional: path) (optional: password)"
                    )
                    return
                path = Path(args[0]).expanduser() if len(args) >= 1 else None
                password = args[1] if len(args) >= 2 else None
                try:
                    from seedpass.core.api import BackupParentSeedRequest

                    self._vault_service.backup_parent_seed(
                        BackupParentSeedRequest(path=path, password=password)
                    )
                    self._clear_failure()
                    if path is not None:
                        self._set_status(f"Parent seed backup written to {path}")
                    else:
                        self._set_status("Parent seed backup/reveal completed")
                except Exception as exc:
                    self._record_failure(
                        "parent-seed-backup failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "doc-export":
                if self._service is None or self._selected_entry_id is None:
                    self._set_status("No entry selected")
                    return
                if len(args) > 1:
                    self._set_status("Usage: doc-export (optional: output_path)")
                    return
                try:
                    entry = self._selected_entry_payload()
                except Exception as exc:
                    self._set_status(str(exc))
                    return
                kind = str(entry.get("kind") or entry.get("type") or "").strip().lower()
                if kind != "document":
                    self._set_status("doc-export requires selected document entry")
                    return
                output_path = args[0] if args else None
                try:
                    dest = self._service.export_document_file(
                        self._selected_entry_id, output_path=output_path
                    )
                    self._clear_failure()
                    self._set_status(f"Exported document to {dest}")
                except Exception as exc:
                    self._record_failure(
                        "doc-export failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "copy":
                if self._service is None:
                    self._set_status("Entry service unavailable")
                    return
                if len(args) < 1 or len(args) > 2:
                    self._set_status("Usage: copy <field> (optional: confirm)")
                    return
                field = args[0].strip()
                confirm = False
                if len(args) == 2:
                    if args[1].strip().lower() != "confirm":
                        self._set_status("Usage: copy <field> (optional: confirm)")
                        return
                    confirm = True
                try:
                    value, sensitive, canonical = self._resolve_copy_field_value(field)
                except Exception as exc:
                    self._set_status(str(exc))
                    return
                if sensitive and not confirm:
                    self._set_status(
                        f"copy {canonical} is sensitive. Re-run with: copy {field} confirm"
                    )
                    return
                if not self._copy_to_clipboard(value):
                    self._set_status("Clipboard unavailable")
                    return
                self._set_status(f"Copied {canonical} to clipboard")
                return

            if cmd == "export-field":
                if self._service is None:
                    self._set_status("Entry service unavailable")
                    return
                if len(args) not in {2, 3}:
                    self._set_status(
                        "Usage: export-field <field> <path> (optional: confirm)"
                    )
                    return
                field = args[0].strip()
                output_path = args[1].strip()
                if not output_path:
                    self._set_status("export-field path is required")
                    return
                confirm = False
                if len(args) == 3:
                    if args[2].strip().lower() != "confirm":
                        self._set_status(
                            "Usage: export-field <field> <path> (optional: confirm)"
                        )
                        return
                    confirm = True
                try:
                    value, sensitive, canonical = self._resolve_copy_field_value(field)
                except Exception as exc:
                    self._set_status(str(exc))
                    return
                if sensitive and not confirm:
                    self._set_status(
                        f"export-field {canonical} is sensitive. Re-run with: export-field {field} {output_path} confirm"
                    )
                    return
                try:
                    destination = self._export_value_to_path(value, output_path)
                    self._set_status(f"Exported {canonical} to {destination}")
                except Exception as exc:
                    self._record_failure(
                        "export-field failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
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
                    else:
                        self._selected_entry_id = int(current_id)
                        entry = self._service.retrieve_entry(int(current_id))
                        self._selected_entry = (
                            dict(entry) if isinstance(entry, dict) else {}
                        )
                        self._update_filters_panel()
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
                return

            if cmd == "managed-load":
                if self._service is None:
                    self._set_status("Entry service unavailable")
                    return
                if len(args) > 1:
                    self._set_status("Usage: managed-load (optional: entry_id)")
                    return
                if len(args) == 1:
                    try:
                        entry_id = int(args[0])
                    except ValueError:
                        self._set_status("managed-load entry_id must be an integer")
                        return
                else:
                    if self._selected_entry_id is None:
                        self._set_status(
                            "managed-load requires a selected managed account entry"
                        )
                        return
                    entry_id = int(self._selected_entry_id)

                loader = getattr(self._service, "load_managed_account", None)
                if not callable(loader):
                    self._set_status(
                        "Entry service does not support managed account session loading"
                    )
                    return
                entry = self._service.retrieve_entry(entry_id)
                kind = (
                    self._normalize_kind_token(entry.get("kind") or entry.get("type"))
                    if isinstance(entry, dict)
                    else ""
                )
                if kind not in {"managed_account", "seed"}:
                    self._set_status("Selected entry is not a managed account or seed")
                    return
                managed_fp = (
                    str(entry.get("fingerprint") or "").strip()
                    if isinstance(entry, dict)
                    else ""
                )
                try:
                    loader(entry_id)
                    self._managed_session_stack.append(
                        {
                            "entry_id": int(entry_id),
                            "fingerprint": managed_fp,
                        }
                    )
                    self._managed_session_entry_id = int(entry_id)
                    self._load_entries(query="", reset_page=True)
                    self._clear_failure()
                    self._set_status(
                        f"Loaded managed account session from entry #{entry_id}"
                    )
                except Exception as exc:
                    self._record_failure(
                        "managed-load failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
                        hint="Press 'x' to retry.",
                    )
                return

            if cmd == "managed-exit":
                if self._service is None:
                    self._set_status("Entry service unavailable")
                    return
                if args:
                    self._set_status("Usage: managed-exit")
                    return
                exiter = getattr(self._service, "exit_managed_account", None)
                if not callable(exiter):
                    self._set_status(
                        "Entry service does not support managed account session exit"
                    )
                    return
                try:
                    exiter()
                    if self._managed_session_stack:
                        self._managed_session_stack.pop()
                    if self._managed_session_stack:
                        self._managed_session_entry_id = int(
                            self._managed_session_stack[-1].get("entry_id", 0)
                        )
                    else:
                        self._managed_session_entry_id = None
                    self._load_entries(query="", reset_page=True)
                    self._clear_failure()
                    self._set_status("Exited managed account session")
                except Exception as exc:
                    self._record_failure(
                        "managed-exit failed",
                        exc,
                        retry=lambda: self._run_palette_command(raw),
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
            if cmd == "reveal":
                if len(args) > 1 or (len(args) == 1 and args[0].lower() != "confirm"):
                    self._set_status("Usage: reveal [confirm]")
                    return
                confirm = len(args) == 1 and args[0].lower() == "confirm"
                self.action_reveal_selected(confirm=confirm)
                return
            if cmd == "qr":
                mode = "default"
                confirm = False
                for token in args:
                    value = token.strip().lower()
                    if value in {"public", "private"}:
                        mode = value
                        continue
                    if value == "confirm":
                        confirm = True
                        continue
                    self._set_status("Usage: qr [public|private] [confirm]")
                    return
                self.action_show_qr(mode=mode, confirm=confirm)
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
            if self.totp_board_open:
                self._refresh_totp_board(force_reload=True)

        def action_toggle_help(self) -> None:
            if self.palette_open:
                self._set_palette_visible(False)
            self.help_open = not self.help_open
            self._update_help_overlay()
            self._set_status("Help opened" if self.help_open else "Help closed")

        def action_focus_left(self) -> None:
            if self._sidebar_collapsed:
                self._set_status("Sidebar is collapsed. Press Ctrl+B to expand.")
                return
            self._focus_pane = "left"
            self._apply_focus_style()
            self._set_status("Focused left pane")

        def action_toggle_sidebar(self) -> None:
            self._set_sidebar_collapsed(not self._sidebar_collapsed)
            if self._sidebar_collapsed:
                self._set_status("Sidebar collapsed")
            else:
                self._set_status("Sidebar expanded")

        def action_profile_tree_next(self) -> None:
            if self._sidebar_collapsed:
                self._set_status("Sidebar is collapsed. Press Ctrl+B to expand.")
                return
            if self._focus_pane != "left":
                self._set_status("Focus left pane first (press 1)")
                return
            self._refresh_profile_tree()
            nodes = self._profile_tree_visible_nodes()
            if not nodes:
                self._set_status("No profiles available")
                return
            self._profile_tree_cursor = (self._profile_tree_cursor + 1) % len(nodes)
            selected = nodes[self._profile_tree_cursor]
            self._update_filters_panel()
            self._set_status(self._profile_tree_selection_text(selected))

        def action_profile_tree_prev(self) -> None:
            if self._sidebar_collapsed:
                self._set_status("Sidebar is collapsed. Press Ctrl+B to expand.")
                return
            if self._focus_pane != "left":
                self._set_status("Focus left pane first (press 1)")
                return
            self._refresh_profile_tree()
            nodes = self._profile_tree_visible_nodes()
            if not nodes:
                self._set_status("No profiles available")
                return
            self._profile_tree_cursor = (self._profile_tree_cursor - 1) % len(nodes)
            selected = nodes[self._profile_tree_cursor]
            self._update_filters_panel()
            self._set_status(self._profile_tree_selection_text(selected))

        def action_profile_tree_open(self) -> None:
            if self._sidebar_collapsed:
                self._set_status("Sidebar is collapsed. Press Ctrl+B to expand.")
                return
            if self._focus_pane != "left":
                self._set_status("Focus left pane first (press 1)")
                return
            self._refresh_profile_tree()
            nodes = self._profile_tree_visible_nodes()
            if not nodes:
                self._set_status("No profiles available")
                return
            self._profile_tree_cursor = min(
                max(0, self._profile_tree_cursor), len(nodes) - 1
            )
            selected = nodes[self._profile_tree_cursor]
            selected_kind = str(selected.get("kind", ""))
            if selected_kind in {"managed", "agent"}:
                target_entry = int(selected.get("entry_id", 0))
                if target_entry <= 0:
                    self._set_status("Selected tree entry is invalid")
                    return
                self._show_entry(target_entry)
                self._focus_pane = "center"
                self._apply_focus_style()
                self.query_one("#entry-list", ListView).focus()
                self._set_status(f"Opened tree entry {target_entry}")
                return
            if self._profile_service is None:
                self._set_status("Profile service unavailable")
                return
            target = str(selected.get("fingerprint", ""))
            if target == "(default)":
                self._set_status("No switch needed for default profile")
                return
            if target == self._active_profile_key():
                self._set_status(f"Profile already active: {target}")
                return
            try:
                from seedpass.core.api import ProfileSwitchRequest

                self._remember_sidebar_for_active_profile()
                self._profile_service.switch_profile(
                    ProfileSwitchRequest(fingerprint=target, password=None)
                )
                self._active_profile_fp = target
                self._root_profile_fp = self._active_profile_key()
                self._managed_session_stack = []
                self._managed_session_entry_id = None
                self._restore_filter_for_active_profile(default_filter="all")
                self._restore_sidebar_for_active_profile(default_collapsed=False)
                self._clear_failure()
                self._load_entries(self._last_query, reset_page=True)
                self._refresh_profile_tree()
                self._set_status(f"Switched profile to {target}")
            except Exception as exc:
                self._record_failure(
                    "profile-tree-open failed",
                    exc,
                    retry=self.action_profile_tree_open,
                    hint="Press 'x' to retry.",
                )

        def action_profile_tree_preview(self) -> None:
            if self._sidebar_collapsed:
                self._set_status("Sidebar is collapsed. Press Ctrl+B to expand.")
                return
            self._refresh_profile_tree()
            nodes = self._profile_tree_visible_nodes()
            if not nodes:
                self._set_status("No profiles available")
                return
            self._profile_tree_cursor = min(
                max(0, self._profile_tree_cursor), len(nodes) - 1
            )
            selected = nodes[self._profile_tree_cursor]
            self._update_filters_panel()
            self._set_status(self._profile_tree_selection_text(selected))

        def action_profile_tree_toggle(self) -> None:
            if self._sidebar_collapsed:
                self._set_status("Sidebar is collapsed. Press Ctrl+B to expand.")
                return
            if self._focus_pane != "left":
                self._set_status("Focus left pane first (press 1)")
                return
            self._refresh_profile_tree()
            nodes = self._profile_tree_visible_nodes()
            if not nodes:
                return
            self._profile_tree_cursor = min(
                max(0, self._profile_tree_cursor), len(nodes) - 1
            )
            selected = nodes[self._profile_tree_cursor]
            if selected.get("kind") == "profile":
                fp = str(selected.get("fingerprint", ""))
                is_expanded = self._profile_tree_expanded.get(fp, False)
                self._profile_tree_expanded[fp] = not is_expanded
                state = "Expanded" if not is_expanded else "Collapsed"
                self._update_filters_panel()
                self._set_status(f"{state} profile branch: {fp}")
            else:
                self._set_status("Only profile nodes can be expanded/collapsed")

        def action_focus_center(self) -> None:
            self._focus_pane = "center"
            self._apply_focus_style()
            self.query_one("#entry-list", ListView).focus()
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
            self._set_filter_menu_visible(False)
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
            self._set_filter_menu_visible(False)
            self._focus_pane = "center"
            self._apply_focus_style()
            self.query_one("#search", Input).focus()

        def action_toggle_filter_menu(self) -> None:
            if self.editing_document:
                self._set_status("Finish document edit before changing filters")
                return
            filter_input = self.query_one("#kind-filter-input", Input)
            self._set_filter_menu_visible(filter_input.has_class("hidden"))

        def action_cycle_filter(self) -> None:
            order = [
                "all",
                "secrets",
                "docs",
                "keys",
                "2fa",
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
            self._remember_filter_for_active_profile()
            self._load_entries(query=self._last_query, reset_page=True)
            self._set_status(f"Applied filter: {self.filter_kind}")

        def _open_palette_with_prefix(self, prefix: str, status: str) -> None:
            if self.editing_document:
                self._set_status("Finish document edit before opening shortcuts")
                return
            if self.help_open:
                self.help_open = False
                self._update_help_overlay()
            self._set_palette_visible(True)
            self._focus_pane = "center"
            self._apply_focus_style()
            palette = self.query_one("#command-palette", Input)
            palette.value = prefix
            palette.cursor_position = len(prefix)
            self._set_status(status)

        def action_shortcut_settings(self) -> None:
            self._open_palette_with_prefix("setting-", "Settings shortcut opened")

        def action_toggle_settings(self) -> None:
            if self._session_locked:
                self._set_status("Vault is locked. Run: unlock <password>")
                return
            self.push_screen(SettingsScreen())
            self._set_status("Opened settings screen")

        def action_maximize_inspector(self) -> None:
            if self._session_locked:
                self._set_status("Vault is locked. Run: unlock <password>")
                return
            if self._selected_entry_id is None:
                self._set_status("Select an entry first to maximize")
                return
            self.push_screen(InspectorScreen())
            self._set_status(f"Maximized entry #{self._selected_entry_id}")

        def action_shortcut_add_entry(self) -> None:
            self._open_palette_with_prefix("add-", "Add-entry shortcut opened")

        def action_shortcut_create_seed(self) -> None:
            self._open_palette_with_prefix("add-seed ", "Create-seed shortcut opened")

        def action_shortcut_remove_seed(self) -> None:
            self._open_palette_with_prefix(
                "profile-remove ", "Remove-seed shortcut opened"
            )

        def action_shortcut_hide_reveal(self) -> None:
            self.action_reveal_selected()

        def action_shortcut_export_data(self) -> None:
            self._open_palette_with_prefix("db-export ", "Export shortcut opened")

        def action_shortcut_import_data(self) -> None:
            self._open_palette_with_prefix("db-import ", "Import shortcut opened")

        def action_shortcut_backup_data(self) -> None:
            self._open_palette_with_prefix(
                "parent-seed-backup ", "Backup shortcut opened"
            )

        def action_cycle_search_mode(self) -> None:
            if self._semantic_service is None:
                self._set_status("Semantic service unavailable")
                return
            modes = ["keyword", "hybrid", "semantic"]
            current = str(self._semantic_mode or "keyword").strip().lower()
            idx = modes.index(current) if current in modes else 0
            target = modes[(idx + 1) % len(modes)]
            setter = getattr(self._semantic_service, "set_mode", None)
            if not callable(setter):
                self._set_status("Semantic service does not support search mode")
                return
            try:
                setter(target)
            except Exception as exc:
                self._record_failure(
                    "search-mode failed",
                    exc,
                    retry=self.action_cycle_search_mode,
                    hint="Press 'x' to retry.",
                )
                return
            self._refresh_semantic_state()
            self._update_top_ribbon()
            self._update_grid_heading()
            self._clear_failure()
            self._set_status(f"Search mode set to {self._semantic_mode}")

        def action_cycle_archive_scope(self) -> None:
            if self.editing_document:
                self._set_status("Finish document edit before changing archive scope")
                return
            order = ["active", "all", "archived"]
            idx = order.index(self.archive_scope) if self.archive_scope in order else 0
            self.archive_scope = order[(idx + 1) % len(order)]
            self._load_entries(query=self._last_query, reset_page=True)
            self._set_status(f"Applied archive filter: {self.archive_scope}")

        def action_toggle_density(self) -> None:
            if self.editing_document:
                self._set_status("Finish document edit before changing density")
                return
            self._density_mode = (
                "comfortable" if self._density_mode == "compact" else "compact"
            )
            self._render_current_page(preserve_selected=True)
            self._update_filters_panel()
            self._set_status(f"Density: {self._density_mode}")

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

        def action_reveal_selected(self, confirm: bool = False) -> None:
            if self._session_locked:
                self._set_status("Vault is locked. Run: unlock <password>")
                return
            if not self._select_highlighted_entry_for_sensitive_action():
                self._set_inspector_side_visible(True)
                self._set_secret_panel(
                    "No entry selected.\n\nSelect an entry, then press 'v' to reveal.",
                    state="HIDDEN",
                )
                self._set_status("No entry selected")
                return
            if isinstance(self._selected_entry, dict):
                kind = self._entry_kind(self._selected_entry)
                if not self._entry_uses_sensitive_panel(kind):
                    self._set_status(f"Reveal not supported for kind: {kind}")
                    return
            if not confirm and isinstance(self._selected_entry, dict):
                kind = self._entry_kind(self._selected_entry)
                entry_id = int(self._selected_entry_id or 0)
                requires_confirm = self._requires_confirm(
                    kind=kind, include_qr=False, qr_mode="default"
                )
                if requires_confirm:
                    shortcut_confirmed = self._consume_pending_sensitive_confirm(
                        action="reveal", entry_id=entry_id
                    )
                    if not shortcut_confirmed:
                        self._pending_sensitive_confirm = (
                            "reveal",
                            entry_id,
                            float(self._time_now()),
                        )
                        self._set_secret_panel(
                            "Sensitive reveal hidden.\n"
                            "Confirmation required for this action.\n"
                            "Press 'v' again to confirm (expires in 8s), "
                            "or run: reveal confirm",
                            state="HIDDEN",
                        )
                        self._set_status(
                            "Sensitive reveal requires confirmation. Press 'v' again."
                        )
                        return
                    confirm = True
            self._show_sensitive_panel(include_qr=False, confirm=confirm)

        def action_show_qr(self, mode: str = "default", confirm: bool = False) -> None:
            if self._session_locked:
                self._set_status("Vault is locked. Run: unlock <password>")
                return
            if not self._select_highlighted_entry_for_sensitive_action():
                self._set_inspector_side_visible(True)
                self._set_secret_panel(
                    "No entry selected.\n\nSelect an entry, then press 'g' to show QR.",
                    state="HIDDEN",
                )
                self._set_status("No entry selected")
                return
            if isinstance(self._selected_entry, dict):
                kind = self._entry_kind(self._selected_entry)
                if not self._entry_uses_sensitive_panel(kind):
                    self._set_status(f"QR not supported for kind: {kind}")
                    return
            self._show_sensitive_panel(include_qr=True, qr_mode=mode, confirm=confirm)

        def action_toggle_totp_board(self) -> None:
            if self.editing_document:
                self._set_status("Finish document edit before opening 2FA board")
                return
            target = not self.totp_board_open
            self._set_totp_board_visible(target)
            self._focus_pane = "right"
            self._apply_focus_style()
            if target:
                self._set_status("2FA board opened")
            else:
                self._set_status("2FA board closed")

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
                else:
                    self._selected_entry_id = int(current_id)
                    entry = self._service.retrieve_entry(int(current_id))
                    self._selected_entry = (
                        dict(entry) if isinstance(entry, dict) else {}
                    )
                    self._update_filters_panel()
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
            filter_input = self.query_one("#kind-filter-input", Input)
            if not filter_input.has_class("hidden"):
                self._set_filter_menu_visible(False)
                self._set_status("Filter menu closed")
                return
            if self.help_open:
                self.help_open = False
                self._update_help_overlay()
                self._set_status("Help closed")
                return
            if self.totp_board_open:
                self._set_totp_board_visible(False)
                self._set_status("2FA board closed")
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

        def on_button_pressed(self, event: Button.Pressed) -> None:
            if event.button.id == "sidebar-toggle":
                self.action_toggle_sidebar()

        def on_click(self, event: Any) -> None:
            target = getattr(event, "widget", None) or getattr(event, "control", None)
            if getattr(target, "id", "") != "action-strip":
                return
            x = int(getattr(event, "x", -1) or -1)
            y = int(getattr(event, "y", -1) or -1)
            self._handle_action_strip_click(x, y)

        def on_text_area_changed(self, _event: Any) -> None:
            self._mark_doc_dirty(True)

        def on_resize(self, event: Any) -> None:
            width = int(getattr(getattr(event, "size", None), "width", 0) or 0)
            height = int(getattr(getattr(event, "size", None), "height", 0) or 0)
            self._update_responsive_layout(width=width, height=height)

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
            if event.input.id == "kind-filter-input":
                self.filter_kind = self._normalize_filter_kind(event.value.strip())
                self._remember_filter_for_active_profile()
                self._set_filter_menu_visible(False)
                self._update_filters_panel()
                self._load_entries(query=self._last_query, reset_page=True)
                self._set_status(f"Applied filter: {self.filter_kind}")
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

        def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
            if self.editing_document:
                return
            item = event.item
            if isinstance(item, EntryListItem):
                self._show_entry(item.entry_index)

    app = SeedPassTuiV2()
    if callable(app_hook):
        app_hook(app)
        return True
    app.run()
    return True
