from __future__ import annotations
from typing import Any
from textual.app import ComposeResult
from textual.widgets import Static, Label, Button
from textual.containers import Vertical, Horizontal
from textual.reactive import reactive


class BaseBoard(Static):
    """Base class for all specialized entry boards."""

    entry_data = reactive[dict[str, Any]]({})
    reveal_data = reactive[dict[str, Any]]({})

    def watch_entry_data(self, old: dict, new: dict) -> None:
        self.update_board()

    def watch_reveal_data(self, old: dict, new: dict) -> None:
        self.update_board()

    def update_board(self) -> None:
        pass


class InspectorHeader(Static):
    """Reusable high-fidelity header matching the UI Board mockups."""

    DEFAULT_CSS = """
    InspectorHeader {
        height: 3;
        layout: horizontal;
        margin-bottom: 1;
        background: #000000;
        color: #ffffff;
        border-bottom: solid #ffffff;
    }
    .title-block { width: 30%; height: 3; }
    .title-text { text-style: bold; }
    .type-text { color: #aaaaaa; }
    
    .meta-block { width: 1fr; layout: horizontal; height: 3; }
    .meta-item { width: 1fr; text-align: left; }
    
    .edit-btn { background: #ffffff; color: #000000; padding: 0 2; height: 1; margin-top: 1; margin-right: 1; text-style: bold; }
    """

    def compose(self) -> ComposeResult:
        with Vertical(classes="title-block"):
            yield Label("Title", id="hdr-title", classes="title-text")
            yield Label("Type", id="hdr-type", classes="type-text")
        with Horizontal(classes="meta-block"):
            yield Label(
                "[b]Date Modified[/b]\nYYYY-MM-DD", id="hdr-date", classes="meta-item"
            )
            yield Label("[b]Black Listed? No[/b]", id="hdr-bl", classes="meta-item")
            yield Label("[b]Index Num*:[/b]\n0", id="hdr-idx", classes="meta-item")
            yield Label("[b]Entry Num:[/b]\n1", id="hdr-enum", classes="meta-item")
        yield Label("[@click=app.edit_selected]Edit[/]", classes="edit-btn")

    def update_data(self, entry: dict, kind_label: str):
        if not self.is_mounted:
            return
        try:
            self.query_one("#hdr-title", Label).update(
                f"[b]{entry.get('label', 'Untitled')}[/b]"
            )
            self.query_one("#hdr-type", Label).update(kind_label)
            idx = str(entry.get("id", "N/A"))
            self.query_one("#hdr-idx", Label).update(f"[b]Index Num*:[/b]\n{idx}")
            self.query_one("#hdr-enum", Label).update(f"[b]Entry Num:[/b]\n{idx}")
        except Exception:
            pass


class IdleBoard(BaseBoard):
    """Shown when no entry is selected."""

    def compose(self) -> ComposeResult:
        yield Label(
            "\n\n[b]Inspector Idle[/b]\n\nSelect an entry from the grid\nto view details.",
            id="idle-text",
        )


class PasswordBoard(BaseBoard):
    """Matches 'Password Board.png' mockup."""

    DEFAULT_CSS = """
    PasswordBoard {
        background: #000000;
        color: #ffffff;
        padding: 0 1;
        height: 1fr;
    }
    .board-body { layout: horizontal; height: 1fr; }
    .left-col { width: 1fr; margin-right: 2; height: 1fr; }
    .right-col { width: 1fr; border: solid #ffffff; padding: 1; height: 1fr; }
    
    .field-box { border: solid #ffffff; padding: 0 1; margin-bottom: 1; height: auto; }
    .field-box.highlight { background: #ffffff; color: #000000; }
    .field-title { text-style: bold; }
    .field-row { layout: horizontal; }
    .field-val { width: 1fr; }
    .action-btn { background: #000000; color: #ffffff; padding: 0 1; margin-left: 1; }
    """

    def compose(self) -> ComposeResult:
        yield InspectorHeader(id="password-header")
        with Horizontal(classes="board-body"):
            with Vertical(classes="left-col"):
                with Vertical(classes="field-box highlight"):
                    yield Label("Password*", classes="field-title")
                    with Horizontal(classes="field-row"):
                        yield Label(
                            "**********", id="fld-pass-val", classes="field-val"
                        )
                        yield Label(
                            "[@click=app.copy_selected]Copy[/]", classes="action-btn"
                        )
                        yield Label(
                            "[@click=app.add_entry]Create New[/]", classes="action-btn"
                        )
                with Vertical(classes="field-box"):
                    yield Label("Username*", classes="field-title")
                    yield Label("-", id="fld-user-val")
                with Vertical(classes="field-box"):
                    yield Label("URL", classes="field-title")
                    yield Label("-", id="fld-url-val")
                with Vertical(classes="field-box"):
                    yield Label("Tags", classes="field-title")
                    yield Label("-", id="fld-tags-val")
            with Vertical(classes="right-col"):
                yield Label("Notes", classes="field-title")
                yield Label("", id="fld-notes-val")

    def update_board(self) -> None:
        if not self.is_mounted:
            return
        d = self.entry_data
        r = self.reveal_data

        try:
            self.query_one("#password-header", InspectorHeader).update_data(
                d, "Password"
            )

            pwd = "[b]**********[/b] (v to reveal)"
            if r.get("content"):
                pwd = r.get("content")

            self.query_one("#fld-pass-val", Label).update(pwd)
            self.query_one("#fld-user-val", Label).update(d.get("username", "-"))
            self.query_one("#fld-url-val", Label).update(d.get("url", "-"))

            tags = d.get("tags", [])
            tag_str = ", ".join(tags) if isinstance(tags, list) else str(tags)
            self.query_one("#fld-tags-val", Label).update(tag_str or "-")

            notes = d.get("notes", "")
            self.query_one("#fld-notes-val", Label).update(notes)
        except Exception:
            pass


class TotpBoard(BaseBoard):
    """Matches '2FA Board.png' mockup."""

    DEFAULT_CSS = """
    TotpBoard { background: #000000; color: #ffffff; padding: 0 1; height: 1fr; }
    .board-body { layout: horizontal; height: 1fr; }
    .left-col { width: 1fr; margin-right: 2; height: 1fr; }
    .right-col { width: 1fr; border: solid #ffffff; padding: 1; height: 1fr; content-align: center middle; }
    .qr-text { text-align: center; }
    .field-box { border: solid #ffffff; padding: 0 1; margin-bottom: 1; height: auto; }
    .field-box.highlight { background: #ffffff; color: #000000; }
    .field-title { text-style: bold; }
    .field-row { layout: horizontal; }
    .field-val { width: 1fr; }
    .action-btn { background: #000000; color: #ffffff; padding: 0 1; margin-left: 1; }
    """

    def compose(self) -> ComposeResult:
        yield InspectorHeader(id="totp-header")
        with Horizontal(classes="board-body"):
            with Vertical(classes="left-col"):
                with Vertical(classes="field-box highlight"):
                    yield Label("2FA Code*", classes="field-title")
                    with Horizontal(classes="field-row"):
                        yield Label(
                            "------  (30s left)", id="fld-code-val", classes="field-val"
                        )
                        yield Label(
                            "[@click=app.copy_selected]Copy[/]", classes="action-btn"
                        )
                with Vertical(classes="field-box"):
                    yield Label("Secret", classes="field-title")
                    yield Label("-", id="fld-secret-val")
                with Vertical(classes="field-box"):
                    yield Label("Algorithm", classes="field-title")
                    yield Label("SHA1", id="fld-algo-val")
            with Vertical(classes="right-col"):
                yield Label("QR Code (Press g)", id="fld-qr-val", classes="qr-text")

    def update_board(self) -> None:
        if not self.is_mounted:
            return
        d = self.entry_data
        r = self.reveal_data
        app = self.app

        try:
            self.query_one("#totp-header", InspectorHeader).update_data(d, "2FA")

            code = "------"
            if app.services.get("entry") and not app.session_locked:
                try:
                    code = app.services["entry"].get_totp_code(d.get("id"))
                except:
                    pass
            import time

            remaining = 30 - (int(time.time()) % 30)
            self.query_one("#fld-code-val", Label).update(
                f"[b]{code}[/b]  ({remaining}s left)"
            )

            secret = "[b]**********[/b] (v to reveal)"
            if r.get("content") and "##" not in r.get("content"):
                secret = r.get("content")

            self.query_one("#fld-secret-val", Label).update(secret)
            self.query_one("#fld-algo-val", Label).update(
                d.get("algorithm", "SHA1").upper()
            )

            qr_content = "QR Code (Press g)"
            if r.get("content") and "##" in r.get("content"):
                qr_content = r.get("content")
            self.query_one("#fld-qr-val", Label).update(qr_content)

        except Exception:
            pass


class NoteBoard(BaseBoard):
    """Matches 'Note Board.png' mockup."""

    DEFAULT_CSS = """
    NoteBoard { background: #000000; color: #ffffff; padding: 0 1; height: 1fr; }
    .board-body { layout: horizontal; height: 1fr; border: solid #ffffff; padding: 1; }
    """

    def compose(self) -> ComposeResult:
        yield InspectorHeader(id="note-header")
        with Vertical(classes="board-body"):
            yield Label("Content", id="fld-content-val")

    def update_board(self) -> None:
        if not self.is_mounted:
            return
        d = self.entry_data
        try:
            kind_label = "Note" if d.get("kind", "") == "note" else "Document"
            self.query_one("#note-header", InspectorHeader).update_data(d, kind_label)
            self.query_one("#fld-content-val", Label).update(d.get("content", ""))
        except Exception:
            pass


class SeedBoard(BaseBoard):
    """Matches 'BIP-39 Seed Board.png' mockup."""

    DEFAULT_CSS = """
    SeedBoard { background: #000000; color: #ffffff; padding: 0 1; height: 1fr; }
    .board-body { layout: horizontal; height: 1fr; }
    .left-col { width: 1fr; margin-right: 2; height: 1fr; }
    .right-col { width: 1fr; border: solid #ffffff; padding: 1; height: 1fr; content-align: center middle; }
    .qr-text { text-align: center; }
    .field-box { border: solid #ffffff; padding: 0 1; margin-bottom: 1; height: auto; }
    .field-box.highlight { background: #ffffff; color: #000000; }
    .field-title { text-style: bold; }
    .field-row { layout: horizontal; }
    .field-val { width: 1fr; }
    .action-btn { background: #000000; color: #ffffff; padding: 0 1; margin-left: 1; }
    """

    def compose(self) -> ComposeResult:
        yield InspectorHeader(id="seed-header")
        with Horizontal(classes="board-body"):
            with Vertical(classes="left-col"):
                with Vertical(classes="field-box highlight"):
                    yield Label("Seed Phrase*", classes="field-title")
                    with Horizontal(classes="field-row"):
                        yield Label(
                            "[HIDDEN]", id="fld-phrase-val", classes="field-val"
                        )
                        yield Label(
                            "[@click=app.copy_selected]Copy[/]", classes="action-btn"
                        )
                with Vertical(classes="field-box"):
                    yield Label("Fingerprint", classes="field-title")
                    yield Label("-", id="fld-fp-val")
                with Vertical(classes="field-box"):
                    yield Label("Word Count", classes="field-title")
                    yield Label("24", id="fld-wc-val")
            with Vertical(classes="right-col"):
                yield Label("QR Code (Press gg)", id="fld-qr-val", classes="qr-text")

    def update_board(self) -> None:
        if not self.is_mounted:
            return
        d = self.entry_data
        r = self.reveal_data
        try:
            kind_label = (
                "BIP-39"
                if d.get("kind", "") in {"seed", "managed_account"}
                else d.get("kind", "Seed")
            )
            self.query_one("#seed-header", InspectorHeader).update_data(
                d, kind_label.capitalize()
            )

            phrase = "[b]**********[/b] (vv to reveal)"
            if r.get("content") and "##" not in r.get("content"):
                phrase = r.get("content")

            self.query_one("#fld-phrase-val", Label).update(phrase)
            self.query_one("#fld-fp-val", Label).update(d.get("fingerprint", "-"))
            self.query_one("#fld-wc-val", Label).update(str(d.get("word_count", 24)))

            qr_content = "QR Code (Press gg)"
            if r.get("content") and "##" in r.get("content"):
                qr_content = r.get("content")
            self.query_one("#fld-qr-val", Label).update(qr_content)
        except Exception:
            pass


class SshBoard(BaseBoard):
    """Matches 'SSH Board.png' mockup."""

    DEFAULT_CSS = """
    SshBoard { background: #000000; color: #ffffff; padding: 0 1; height: 1fr; }
    .board-body { layout: horizontal; height: 1fr; }
    .left-col { width: 1fr; margin-right: 2; height: 1fr; }
    .right-col { width: 1fr; border: solid #ffffff; padding: 1; height: 1fr; }
    .field-box { border: solid #ffffff; padding: 0 1; margin-bottom: 1; height: auto; }
    .field-box.highlight { background: #ffffff; color: #000000; }
    .field-title { text-style: bold; }
    .field-row { layout: horizontal; }
    .field-val { width: 1fr; }
    .action-btn { background: #000000; color: #ffffff; padding: 0 1; margin-left: 1; }
    """

    def compose(self) -> ComposeResult:
        yield InspectorHeader(id="ssh-header")
        with Horizontal(classes="board-body"):
            with Vertical(classes="left-col"):
                with Vertical(classes="field-box highlight"):
                    yield Label("Private Key*", classes="field-title")
                    with Horizontal(classes="field-row"):
                        yield Label("[HIDDEN]", id="fld-priv-val", classes="field-val")
                        yield Label(
                            "[@click=app.copy_selected]Copy[/]", classes="action-btn"
                        )
                with Vertical(classes="field-box"):
                    yield Label("Public Key", classes="field-title")
                    with Horizontal(classes="field-row"):
                        yield Label("[PREVIEW]", id="fld-pub-val", classes="field-val")
                        yield Label(
                            "[@click=app.copy_selected]Copy[/]", classes="action-btn"
                        )
                with Vertical(classes="field-box"):
                    yield Label("Key Type", classes="field-title")
                    yield Label("Ed25519", id="fld-type-val")
            with Vertical(classes="right-col"):
                yield Label("Notes", classes="field-title")
                yield Label("", id="fld-notes-val")

    def update_board(self) -> None:
        if not self.is_mounted:
            return
        d = self.entry_data
        r = self.reveal_data
        try:
            self.query_one("#ssh-header", InspectorHeader).update_data(d, "SSH")

            priv = "[b]**********[/b] (vv to reveal)"
            if r.get("content"):
                priv = r.get("content")
            self.query_one("#fld-priv-val", Label).update(priv)

            pub = d.get("public_key", "[PREVIEW]")
            if len(pub) > 30:
                pub = pub[:30] + "..."
            self.query_one("#fld-pub-val", Label).update(pub)

            self.query_one("#fld-type-val", Label).update(
                d.get("key_type", "RSA/Ed25519")
            )
            self.query_one("#fld-notes-val", Label).update(d.get("notes", ""))
        except Exception:
            pass


class PgpBoard(BaseBoard):
    """Matches 'PGP Board.png' mockup."""

    DEFAULT_CSS = SshBoard.DEFAULT_CSS.replace("SshBoard", "PgpBoard")

    def compose(self) -> ComposeResult:
        yield InspectorHeader(id="pgp-header")
        with Horizontal(classes="board-body"):
            with Vertical(classes="left-col"):
                with Vertical(classes="field-box highlight"):
                    yield Label("Private Key*", classes="field-title")
                    with Horizontal(classes="field-row"):
                        yield Label("[HIDDEN]", id="fld-priv-val", classes="field-val")
                        yield Label(
                            "[@click=app.copy_selected]Copy[/]", classes="action-btn"
                        )
                with Vertical(classes="field-box"):
                    yield Label("Fingerprint / ID", classes="field-title")
                    yield Label("-", id="fld-fp-val")
                with Vertical(classes="field-box"):
                    yield Label("Identity", classes="field-title")
                    yield Label("-", id="fld-ident-val")
            with Vertical(classes="right-col"):
                yield Label("Notes", classes="field-title")
                yield Label("", id="fld-notes-val")

    def update_board(self) -> None:
        if not self.is_mounted:
            return
        d = self.entry_data
        r = self.reveal_data
        try:
            self.query_one("#pgp-header", InspectorHeader).update_data(d, "PGP")

            priv = "[b]**********[/b] (vv to reveal)"
            if r.get("content"):
                priv = r.get("content")
            self.query_one("#fld-priv-val", Label).update(priv)

            self.query_one("#fld-fp-val", Label).update(d.get("fingerprint", "-"))
            self.query_one("#fld-ident-val", Label).update(d.get("user_id", "-"))
            self.query_one("#fld-notes-val", Label).update(d.get("notes", ""))
        except Exception:
            pass


class NostrBoard(BaseBoard):
    """Matches 'Nostr Board.png' mockup."""

    DEFAULT_CSS = TotpBoard.DEFAULT_CSS.replace("TotpBoard", "NostrBoard")

    def compose(self) -> ComposeResult:
        yield InspectorHeader(id="nostr-header")
        with Horizontal(classes="board-body"):
            with Vertical(classes="left-col"):
                with Vertical(classes="field-box highlight"):
                    yield Label("nsec (Secret)*", classes="field-title")
                    with Horizontal(classes="field-row"):
                        yield Label("[HIDDEN]", id="fld-nsec-val", classes="field-val")
                        yield Label(
                            "[@click=app.copy_selected]Copy[/]", classes="action-btn"
                        )
                with Vertical(classes="field-box"):
                    yield Label("npub (Public)", classes="field-title")
                    with Horizontal(classes="field-row"):
                        yield Label("-", id="fld-npub-val", classes="field-val")
                        yield Label(
                            "[@click=app.copy_selected]Copy[/]", classes="action-btn"
                        )
                with Vertical(classes="field-box"):
                    yield Label("Hex Key", classes="field-title")
                    yield Label("-", id="fld-hex-val")
            with Vertical(classes="right-col"):
                yield Label("QR Code (Press g)", id="fld-qr-val", classes="qr-text")

    def update_board(self) -> None:
        if not self.is_mounted:
            return
        d = self.entry_data
        r = self.reveal_data
        try:
            self.query_one("#nostr-header", InspectorHeader).update_data(d, "Nostr")

            nsec = "[b]**********[/b] (v to reveal)"
            if r.get("content") and "##" not in r.get("content"):
                nsec = r.get("content")
            self.query_one("#fld-nsec-val", Label).update(nsec)

            npub = d.get("npub", "-")
            if len(npub) > 30:
                npub = npub[:30] + "..."
            self.query_one("#fld-npub-val", Label).update(npub)

            self.query_one("#fld-hex-val", Label).update(d.get("hex", "-"))

            qr_content = "QR Code (Press g)"
            if r.get("content") and "##" in r.get("content"):
                qr_content = r.get("content")
            self.query_one("#fld-qr-val", Label).update(qr_content)
        except Exception:
            pass


class GenericBoard(BaseBoard):
    """Fallback high-fidelity board."""

    DEFAULT_CSS = """
    GenericBoard { background: #000000; color: #ffffff; padding: 0 1; height: 1fr; }
    .board-body { layout: horizontal; height: 1fr; }
    .left-col { width: 1fr; margin-right: 2; height: 1fr; }
    .right-col { width: 1fr; border: solid #ffffff; padding: 1; height: 1fr; }
    .field-box { border: solid #ffffff; padding: 0 1; margin-bottom: 1; height: auto; }
    .field-box.highlight { background: #ffffff; color: #000000; }
    .field-title { text-style: bold; }
    """

    def compose(self) -> ComposeResult:
        yield InspectorHeader(id="generic-header")
        with Horizontal(classes="board-body"):
            with Vertical(classes="left-col"):
                with Vertical(classes="field-box highlight"):
                    yield Label("Revealed Secret", classes="field-title")
                    yield Label("[HIDDEN]", id="fld-secret-val")
                with Vertical(classes="field-box"):
                    yield Label("Details", classes="field-title")
                    yield Label("-", id="fld-details-val")
            with Vertical(classes="right-col"):
                yield Label("Notes", classes="field-title")
                yield Label("", id="fld-notes-val")

    def update_board(self) -> None:
        if not self.is_mounted:
            return
        d = self.entry_data
        r = self.reveal_data
        kind = str(d.get("kind", d.get("type", "Unknown"))).capitalize()

        try:
            self.query_one("#generic-header", InspectorHeader).update_data(d, kind)

            secret = "[HIDDEN] (v to reveal)"
            if r.get("content"):
                secret = rf"{r.get('content')}"
            self.query_one("#fld-secret-val", Label).update(secret)

            details = []
            for k, v in d.items():
                if k not in ("label", "notes", "tags", "kind", "id", "type", "content"):
                    details.append(f"[b]{k.capitalize()}:[/b] {v}")
            self.query_one("#fld-details-val", Label).update("\n".join(details) or "-")

            self.query_one("#fld-notes-val", Label).update(d.get("notes", ""))

        except Exception:
            pass


class BoardContainer(Vertical):
    """
    Reactive container that swaps specialized boards based on entry kind.
    """

    DEFAULT_CSS = """
    BoardContainer {
        height: 1fr;
        padding: 0;
        margin: 0;
        background: #000000;
        overflow: auto;
    }
    """

    def on_mount(self) -> None:
        self._show_board("idle")

    def update_entry(self, entry_id: int | None) -> None:
        if entry_id is None:
            self._show_board("idle")
            return

        app = self.app
        if "entry" not in app.services:
            return

        entry = app.services["entry"].retrieve_entry(entry_id)
        if not entry:
            self._show_board("idle")
            return

        kind = str(entry.get("kind") or entry.get("type") or "").lower()

        if kind in {"password", "stored_password"}:
            board = self._show_board("password")
        elif kind == "totp":
            board = self._show_board("totp")
        elif kind in {"document", "note"}:
            board = self._show_board("note")
        elif kind in {"seed", "managed_account"}:
            board = self._show_board("seed")
        elif kind == "ssh":
            board = self._show_board("ssh")
        elif kind == "pgp":
            board = self._show_board("pgp")
        elif kind == "nostr":
            board = self._show_board("nostr")
        else:
            board = self._show_board("generic")

        board.entry_data = entry

    def _show_board(self, board_type: str) -> Any:
        self.remove_children()
        mapping = {
            "idle": IdleBoard,
            "password": PasswordBoard,
            "totp": TotpBoard,
            "note": NoteBoard,
            "seed": SeedBoard,
            "ssh": SshBoard,
            "pgp": PgpBoard,
            "nostr": NostrBoard,
            "generic": GenericBoard,
        }
        board_cls = mapping.get(board_type, GenericBoard)
        new_board = board_cls()
        self.mount(new_board)
        return new_board


class LinkedItemsPanel(Vertical):
    """Inspector panel for browsing explicit incoming and outgoing relationships."""

    DEFAULT_CSS = """
    LinkedItemsPanel {
        height: auto;
        max-height: 12;
        min-height: 6;
        background: #111111;
        color: #ffffff;
        border-top: solid #ffffff;
        padding: 1;
    }
    #linked-items-title {
        text-style: bold;
        margin-bottom: 1;
    }
    .linked-summary {
        color: #cccccc;
        margin-bottom: 1;
    }
    .linked-empty {
        color: #aaaaaa;
    }
    .linked-open {
        width: 100%;
        height: auto;
        margin-bottom: 1;
        content-align: left middle;
    }
    """

    def compose(self) -> ComposeResult:
        yield Label("Linked Items", id="linked-items-title")
        yield Label("No linked items.", id="linked-items-summary", classes="linked-summary")
        with Vertical(id="linked-items-list"):
            yield Label("Select an entry to inspect relationships.", classes="linked-empty")

    def update_entry(self, entry_id: int | None) -> None:
        summary_label = self.query_one("#linked-items-summary", Label)
        list_container = self.query_one("#linked-items-list", Vertical)
        list_container.remove_children()

        if entry_id is None:
            summary_label.update("No linked items.")
            list_container.mount(
                Label(
                    "Select an entry to inspect relationships.",
                    classes="linked-empty",
                )
            )
            return

        search = self.app.services.get("search")
        if search is None or not hasattr(search, "linked_neighbors"):
            summary_label.update("Search graph service unavailable.")
            list_container.mount(
                Label(
                    "Linked navigation requires SearchService graph helpers.",
                    classes="linked-empty",
                )
            )
            return

        try:
            neighbors = search.linked_neighbors(entry_id, direction="both", limit=8)
            summary = search.relation_summary(entry_id)
        except Exception as exc:
            summary_label.update(f"Linked navigation failed: {exc}")
            list_container.mount(Label("Unable to load linked items.", classes="linked-empty"))
            return

        outgoing = ", ".join(
            f"{relation}:{count}" for relation, count in summary.get("outgoing", {}).items()
        ) or "none"
        incoming = ", ".join(
            f"{relation}:{count}" for relation, count in summary.get("incoming", {}).items()
        ) or "none"
        summary_label.update(f"Outgoing {outgoing}  |  Incoming {incoming}")

        if not neighbors:
            list_container.mount(Label("No linked items for this entry.", classes="linked-empty"))
            return

        for item in neighbors:
            direction = "->" if item.get("direction") == "outgoing" else "<-"
            relation = str(item.get("relation", "")).strip() or "related_to"
            label = str(item.get("label", "")).strip() or f"Entry #{item.get('entry_id', '?')}"
            kind = str(item.get("kind", "")).strip() or "entry"
            archived = " archived" if item.get("archived") else ""
            line = f"{direction} {relation}  #{item.get('entry_id')}  {label} [{kind}{archived}]"
            list_container.mount(
                Button(
                    f"{line}  |  Open",
                    id=f"linked-open-{int(item.get('entry_id', 0) or 0)}",
                    classes="linked-open",
                )
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""
        if not button_id.startswith("linked-open-"):
            return
        try:
            entry_id = int(button_id.removeprefix("linked-open-"))
        except ValueError:
            self.app.notify("Invalid linked item target", severity="error")
            return
        self.app.selected_entry_id = entry_id
        self.app.notify(f"Opened linked entry #{entry_id}")
