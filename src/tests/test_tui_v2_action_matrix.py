from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("textual")
from textual.widgets import Input, ListView

from seedpass.tui_v2.app import launch_tui2


class MatrixEntryService:
    def __init__(
        self,
        entries: list[dict],
        *,
        fail_search: bool = False,
        fail_links: bool = False,
        fail_archive: bool = False,
        fail_restore: bool = False,
        fail_modify: bool = False,
        fail_add_link: bool = False,
        fail_remove_link: bool = False,
    ) -> None:
        self._entries = {int(entry["id"]): dict(entry) for entry in entries}
        self._links = {
            int(entry["id"]): [dict(link) for link in entry.get("links", [])]
            for entry in entries
        }
        self.fail_search = fail_search
        self.fail_links = fail_links
        self.fail_archive = fail_archive
        self.fail_restore = fail_restore
        self.fail_modify = fail_modify
        self.fail_add_link = fail_add_link
        self.fail_remove_link = fail_remove_link
        self.secret_mode_enabled = False
        self.clipboard_delay = 30
        self.clipboard_values: list[str] = []
        self.managed_load_calls: list[int] = []
        self.managed_exit_calls = 0

    def _next_id(self) -> int:
        return (max(self._entries.keys()) + 1) if self._entries else 1

    def search_entries(
        self,
        query: str,
        kinds: list[str] | None = None,
        *,
        include_archived: bool = False,
        archived_only: bool = False,
    ):
        if self.fail_search:
            raise RuntimeError("search failed")
        q = (query or "").strip().lower()
        rows = []
        for entry_id in sorted(self._entries.keys()):
            entry = self._entries[entry_id]
            kind = str(entry.get("kind", "password"))
            if kinds and kind not in kinds:
                continue
            archived = bool(entry.get("archived", False))
            if archived_only and not archived:
                continue
            if not include_archived and archived:
                continue
            label = str(entry.get("label", ""))
            if q and q not in label.lower():
                continue
            rows.append(
                (
                    entry_id,
                    label,
                    None,
                    None,
                    archived,
                    SimpleNamespace(value=kind),
                )
            )
        return rows

    def retrieve_entry(self, entry_id: int):
        if int(entry_id) not in self._entries:
            return {}
        return dict(self._entries[int(entry_id)])

    def add_entry(
        self,
        label: str,
        length: int,
        username: str | None = None,
        url: str | None = None,
    ) -> int:
        entry_id = self._next_id()
        self._entries[entry_id] = {
            "id": entry_id,
            "kind": "password",
            "label": label,
            "length": int(length),
            "username": username,
            "url": url,
            "archived": False,
        }
        return entry_id

    def add_totp(
        self,
        label: str,
        *,
        index: int | None = None,
        secret: str | None = None,
        period: int = 30,
        digits: int = 6,
        deterministic: bool = False,
    ) -> str:
        _ = (index, deterministic)
        entry_id = self._next_id()
        self._entries[entry_id] = {
            "id": entry_id,
            "kind": "totp",
            "label": label,
            "secret": secret or "JBSWY3DPEHPK3PXP",
            "period": int(period),
            "digits": int(digits),
            "archived": False,
        }
        return f"otpauth://totp/{label}"

    def add_key_value(
        self, label: str, key: str, value: str, *, notes: str = ""
    ) -> int:
        _ = notes
        entry_id = self._next_id()
        self._entries[entry_id] = {
            "id": entry_id,
            "kind": "key_value",
            "label": label,
            "key": key,
            "value": value,
            "archived": False,
        }
        return entry_id

    def add_document(
        self,
        label: str,
        content: str,
        *,
        file_type: str = "txt",
        notes: str = "",
        tags: list[str] | None = None,
        archived: bool = False,
    ) -> int:
        _ = notes
        entry_id = self._next_id()
        self._entries[entry_id] = {
            "id": entry_id,
            "kind": "document",
            "label": label,
            "content": content,
            "file_type": file_type,
            "tags": tags or [],
            "archived": bool(archived),
        }
        return entry_id

    def add_ssh_key(
        self, label: str, *, index: int | None = None, notes: str = ""
    ) -> int:
        _ = (index, notes)
        entry_id = self._next_id()
        self._entries[entry_id] = {
            "id": entry_id,
            "kind": "ssh",
            "label": label,
            "private_key": f"SSH_PRIVATE_{entry_id}",
            "public_key": f"ssh-ed25519 AAAA-{entry_id}",
            "archived": False,
        }
        return entry_id

    def add_pgp_key(
        self,
        label: str,
        *,
        index: int | None = None,
        key_type: str = "ed25519",
        user_id: str = "",
        notes: str = "",
    ) -> int:
        _ = (index, key_type, user_id, notes)
        entry_id = self._next_id()
        self._entries[entry_id] = {
            "id": entry_id,
            "kind": "pgp",
            "label": label,
            "private_key": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "fingerprint": f"FPR-{entry_id}",
            "archived": False,
        }
        return entry_id

    def add_nostr_key(
        self, label: str, *, index: int | None = None, notes: str = ""
    ) -> int:
        _ = (index, notes)
        entry_id = self._next_id()
        self._entries[entry_id] = {
            "id": entry_id,
            "kind": "nostr",
            "label": label,
            "npub": f"npub{entry_id}",
            "nsec": f"nsec{entry_id}",
            "archived": False,
        }
        return entry_id

    def add_seed(
        self,
        label: str,
        *,
        index: int | None = None,
        words: int = 24,
        notes: str = "",
    ) -> int:
        _ = (index, notes)
        word_count = max(12, int(words))
        phrase = " ".join(["abandon"] * (word_count - 1) + ["about"])
        entry_id = self._next_id()
        self._entries[entry_id] = {
            "id": entry_id,
            "kind": "seed",
            "label": label,
            "seed_phrase": phrase,
            "archived": False,
        }
        return entry_id

    def add_managed_account(
        self, label: str, *, index: int | None = None, notes: str = ""
    ) -> int:
        _ = (index, notes)
        entry_id = self._next_id()
        self._entries[entry_id] = {
            "id": entry_id,
            "kind": "managed_account",
            "label": label,
            "seed_phrase": "legal winner thank year wave sausage worth useful legal winner thank yellow",
            "archived": False,
        }
        return entry_id

    def export_document_file(
        self,
        entry_id: int,
        output_path: str | Path | None = None,
        *,
        overwrite: bool = False,
    ) -> Path:
        _ = overwrite
        entry = self._entries[int(entry_id)]
        kind = str(entry.get("kind", ""))
        if kind != "document":
            raise ValueError("Entry is not a document entry")
        name = str(entry.get("label", f"document-{entry_id}")).replace(" ", "_")
        ext = str(entry.get("file_type", "txt")).lstrip(".") or "txt"
        if output_path is None:
            dest = Path.cwd() / f"{name}.{ext}"
        else:
            raw = Path(output_path)
            if raw.suffix:
                dest = raw
            else:
                dest = raw / f"{name}.{ext}"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(str(entry.get("content", "")), encoding="utf-8")
        return dest

    def modify_entry(self, entry_id: int, **kwargs) -> None:
        if self.fail_modify:
            raise RuntimeError("modify failed")
        entry = self._entries[int(entry_id)]
        for key, value in kwargs.items():
            if value is not None:
                entry[key] = value

    def generate_password(self, length: int, entry_id: int) -> str:
        return f"pw-{entry_id}-{length}"

    def get_seed_phrase(self, entry_id: int) -> str:
        entry = self._entries[int(entry_id)]
        return str(entry.get("seed_phrase", "abandon " * 11 + "about")).strip()

    def get_managed_account_seed(self, entry_id: int) -> str:
        entry = self._entries[int(entry_id)]
        return str(
            entry.get(
                "seed_phrase",
                "legal winner thank year wave sausage worth useful legal winner thank yellow",
            )
        ).strip()

    def get_totp_secret(self, entry_id: int) -> str:
        entry = self._entries[int(entry_id)]
        return str(entry.get("secret", "JBSWY3DPEHPK3PXP"))

    def get_totp_code(self, entry_id: int) -> str:
        _ = entry_id
        return "123456"

    def get_ssh_key_pair(self, entry_id: int):
        entry = self._entries[int(entry_id)]
        return (
            str(entry.get("private_key", "SSH_PRIVATE")),
            str(entry.get("public_key", "ssh-ed25519 AAAA...")),
        )

    def get_pgp_key(self, entry_id: int):
        entry = self._entries[int(entry_id)]
        return (
            str(entry.get("private_key", "-----BEGIN PGP PRIVATE KEY BLOCK-----")),
            str(entry.get("fingerprint", "DEADBEEF")),
        )

    def get_nostr_key_pair(self, entry_id: int):
        entry = self._entries[int(entry_id)]
        return (
            str(entry.get("npub", "npub1example")),
            str(entry.get("nsec", "nsec1example")),
        )

    def get_secret_mode_enabled(self) -> bool:
        return self.secret_mode_enabled

    def get_clipboard_clear_delay(self) -> int:
        return self.clipboard_delay

    def copy_to_clipboard(self, value: str) -> bool:
        self.clipboard_values.append(value)
        return True

    def archive_entry(self, entry_id: int) -> None:
        if self.fail_archive:
            raise RuntimeError("archive failed")
        self._entries[int(entry_id)]["archived"] = True

    def restore_entry(self, entry_id: int) -> None:
        if self.fail_restore:
            raise RuntimeError("restore failed")
        self._entries[int(entry_id)]["archived"] = False

    def get_links(self, entry_id: int):
        if self.fail_links:
            raise RuntimeError("links failed")
        return [dict(link) for link in self._links.get(int(entry_id), [])]

    def add_link(
        self,
        entry_id: int,
        target_id: int,
        *,
        relation: str = "related_to",
        note: str = "",
    ):
        if self.fail_add_link:
            raise RuntimeError("link add failed")
        links = self._links.setdefault(int(entry_id), [])
        links.append({"target": int(target_id), "relation": relation, "note": note})
        return [dict(link) for link in links]

    def remove_link(
        self, entry_id: int, target_id: int, *, relation: str | None = None
    ):
        if self.fail_remove_link:
            raise RuntimeError("link remove failed")
        src = self._links.setdefault(int(entry_id), [])
        keep = []
        for link in src:
            if int(link.get("target", -1)) != int(target_id):
                keep.append(link)
                continue
            if relation is not None and str(link.get("relation")) != relation:
                keep.append(link)
        self._links[int(entry_id)] = keep
        return [dict(link) for link in keep]

    def load_managed_account(self, entry_id: int) -> None:
        entry = self._entries.get(int(entry_id), {})
        kind = str(entry.get("kind", ""))
        if kind != "managed_account":
            raise ValueError("Entry is not a managed account")
        self.managed_load_calls.append(int(entry_id))

    def exit_managed_account(self) -> None:
        self.managed_exit_calls += 1


def _build_app(*, service: MatrixEntryService | None = None, factory=None):
    holder: dict[str, object] = {}

    def _hook(app):
        holder["app"] = app

    launched = launch_tui2(
        entry_service_factory=factory if factory is not None else (lambda: service),
        app_hook=_hook,
    )
    assert launched is True
    app = holder.get("app")
    assert app is not None
    return app


def _status(app) -> str:
    return str(app.query_one("#status").render())


@pytest.mark.anyio
async def test_tui2_matrix_init_retry_failure_and_success() -> None:
    calls = {"n": 0}
    svc = MatrixEntryService([{"id": 1, "kind": "document", "label": "Doc"}])

    def _factory():
        calls["n"] += 1
        if calls["n"] < 2:
            raise RuntimeError("boom")
        return svc

    app = _build_app(factory=_factory)
    async with app.run_test() as pilot:
        await pilot.pause()
        assert "Unable to initialize entry service" in _status(app)
        app.action_retry_last_error()
        await pilot.pause()
        assert any(
            "Entry service initialized" in msg
            for msg in getattr(app, "_activity_log", [])
        )
        list_view = app.query_one("#entry-list", ListView)
        assert len(list_view.children) == 1


@pytest.mark.anyio
async def test_tui2_matrix_service_unavailable_and_no_retry() -> None:
    app = _build_app(service=None)
    async with app.run_test() as pilot:
        await pilot.pause()
        assert "Entry service unavailable" in str(
            app.query_one("#entry-detail").render()
        )
        app.action_retry_last_error()
        await pilot.pause()
        assert "No retry action available" in _status(app)


@pytest.mark.anyio
async def test_tui2_matrix_actions_palette_events_and_guards() -> None:
    entries = [
        {
            "id": 1,
            "kind": "document",
            "label": "Doc One",
            "content": "line",
            "file_type": "md",
            "tags": ["a"],
            "links": [
                {"target": 2, "relation": "references", "note": "a-note"},
                {"target": 3, "relation": "contains", "note": ""},
            ],
        },
        {"id": 2, "kind": "password", "label": "Pw Two"},
        {"id": 3, "kind": "key_value", "label": "KV Three"},
    ] + [
        {"id": i, "kind": "document", "label": f"Doc {i}", "content": "x"}
        for i in range(4, 235)
    ]
    svc = MatrixEntryService(entries)
    app = _build_app(service=svc)

    async with app.run_test() as pilot:
        await pilot.pause()

        app.action_toggle_help()
        await pilot.pause()
        assert "Help opened" in _status(app)
        app.action_open_palette()
        await pilot.pause()
        assert "Palette opened" in _status(app)
        app.action_cancel_document_edit()
        await pilot.pause()
        assert "Palette closed" in _status(app)
        app.action_cancel_document_edit()
        await pilot.pause()
        assert app.help_open is False

        app._run_palette_command("")
        app._run_palette_command("open")
        app._run_palette_command("open abc")
        app._run_palette_command("jump")
        app._run_palette_command("jump abc")
        app._run_palette_command("page")
        app._run_palette_command("page abc")
        app._run_palette_command("page 0")
        app._run_palette_command("density")
        app._run_palette_command("density noisy")
        app._run_palette_command("help-commands now")
        app._run_palette_command("onboarding now")
        app._run_palette_command("quickstart now")
        app._run_palette_command("stats now")
        app._run_palette_command("link-filter")
        app._run_palette_command("link-add")
        app._run_palette_command("link-add no")
        app._run_palette_command("link-rm")
        app._run_palette_command("link-rm no")
        app._run_palette_command("add-password")
        app._run_palette_command("add-password Site nope")
        app._run_palette_command("add-totp")
        app._run_palette_command("add-totp Auth bad")
        app._run_palette_command("add-key-value")
        app._run_palette_command("add-document")
        app._run_palette_command("add-ssh")
        app._run_palette_command("add-ssh Host nope")
        app._run_palette_command("add-pgp")
        app._run_palette_command("add-pgp Pgp nope")
        app._run_palette_command("add-nostr")
        app._run_palette_command("add-nostr Nostr nope")
        app._run_palette_command("add-seed")
        app._run_palette_command("add-seed Seed nope")
        app._run_palette_command("add-managed-account")
        app._run_palette_command("add-managed-account Managed nope")
        app._run_palette_command("notes-set")
        app._run_palette_command("notes-clear nope")
        app._run_palette_command("tag-add")
        app._run_palette_command("tag-rm")
        app._run_palette_command("tags-set")
        app._run_palette_command("tags-clear nope")
        app._run_palette_command("field-add")
        app._run_palette_command("field-rm")
        app._run_palette_command("set-field")
        app._run_palette_command("clear-field")
        app._run_palette_command("2fa-board nope")
        app._run_palette_command("2fa-hide nope")
        app._run_palette_command("2fa-refresh nope")
        app._run_palette_command("2fa-copy")
        app._run_palette_command("2fa-copy nope")
        app._run_palette_command("profiles-list")
        app._run_palette_command("profile-switch")
        app._run_palette_command("profile-add")
        app._run_palette_command("profile-remove")
        app._run_palette_command("profile-rename")
        app._run_palette_command("setting-secret on")
        app._run_palette_command("setting-offline on")
        app._run_palette_command("setting-quick-unlock on")
        app._run_palette_command("setting-timeout 300")
        app._run_palette_command("setting-kdf-iterations 100000")
        app._run_palette_command("setting-kdf-mode pbkdf2")
        app._run_palette_command("relay-list")
        app._run_palette_command("npub")
        app._run_palette_command("relay-add wss://relay.example")
        app._run_palette_command("relay-rm 1")
        app._run_palette_command("relay-reset")
        app._run_palette_command("nostr-reset-sync-state")
        app._run_palette_command("nostr-fresh-namespace")
        app._run_palette_command("sync-now")
        app._run_palette_command("sync-bg")
        app._run_palette_command("checksum-verify")
        app._run_palette_command("checksum-update")
        app._run_palette_command("db-export /tmp/seedpass-db.enc")
        app._run_palette_command("db-import /tmp/seedpass-db.enc")
        app._run_palette_command("totp-export /tmp/seedpass-totp.json")
        app._run_palette_command("parent-seed-backup")
        app._run_palette_command("managed-load 1 2")
        app._run_palette_command("managed-load nope")
        app._run_palette_command("managed-exit now")
        app._run_palette_command("session-status now")
        app._run_palette_command("lock now")
        app._run_palette_command("unlock")
        app._run_palette_command("doc-export one two")
        app._run_palette_command("copy")
        app._run_palette_command("copy password nope")
        app._run_palette_command("export-field")
        app._run_palette_command("export-field private /tmp/matrix-key.bad nope")
        app._run_palette_command("filter")
        app._run_palette_command("archive-filter")
        app._run_palette_command("archive-filter bogus")
        app._run_palette_command("unknown-cmd")
        await pilot.pause()

        app._run_palette_command("help")
        app._run_palette_command("help-commands")
        app._run_palette_command("onboarding")
        app._run_palette_command("quickstart")
        app._run_palette_command("stats")
        app._run_palette_command("session-status")
        app._run_palette_command("lock")
        app._run_palette_command("unlock hunter2")
        app._run_palette_command("search Doc")
        app._run_palette_command("density comfortable")
        app._run_palette_command("density compact")
        app._run_palette_command("filter document")
        app._run_palette_command("archive-filter all")
        app._run_palette_command("archive-filter archived")
        app._run_palette_command("archive-filter active")
        app._run_palette_command("page-next")
        app._run_palette_command("page-prev")
        app._run_palette_command("page 2")
        app._run_palette_command("open 1")
        app._run_palette_command("jump 2")
        app._run_palette_command("add-password NewLogin 18 user https://seedpass.dev")
        app._run_palette_command("add-totp NewAuth 30 6 JBSWY3DPEHPK3PXP")
        app._run_palette_command("add-key-value Env API_KEY value")
        app._run_palette_command("add-document Runbook md body")
        app._run_palette_command("add-ssh Host 10")
        app._run_palette_command("add-pgp Pgp 11 ed25519 user@example.com")
        app._run_palette_command("add-nostr Nostr 12")
        app._run_palette_command("add-seed Seed 24 13")
        app._run_palette_command("add-managed-account Managed 14")
        app._run_palette_command('notes-set "matrix note"')
        app._run_palette_command("tag-add matrix")
        app._run_palette_command("tag-rm matrix")
        app._run_palette_command("tags-set m1, m2")
        app._run_palette_command("tags-clear")
        app._run_palette_command("field-add scope admin hidden")
        app._run_palette_command("field-rm scope")
        app._run_palette_command("set-field notes matrix-updated")
        app._run_palette_command("clear-field notes")
        app._run_palette_command("2fa-board")
        app._run_palette_command("2fa-copy 2")
        app._run_palette_command("2fa-refresh")
        app._run_palette_command("2fa-hide")
        app._run_palette_command("doc-export /tmp/seedpass-matrix-export")
        app._run_palette_command("copy content")
        app._run_palette_command("export-field content /tmp/seedpass-matrix-content.txt")
        await pilot.pause()

        app._run_palette_command("open 2")
        app._run_palette_command("copy password confirm")
        app._run_palette_command("export-field password /tmp/seedpass-matrix-password.txt confirm")
        app.action_reveal_selected()
        await pilot.pause()
        assert "pw-2-" in str(app.query_one("#secret-detail").render())
        app.action_show_qr()
        await pilot.pause()
        assert "QR not supported" in str(app.query_one("#secret-detail").render())

        app.action_focus_left()
        app.action_focus_center()
        app.action_focus_right()
        app.action_focus_search()
        app.action_focus_jump()
        await pilot.pause()

        app.action_next_page()
        app.action_prev_page()
        app.action_cycle_archive_scope()
        app.action_cycle_archive_scope()
        app.action_cycle_archive_scope()
        await pilot.pause()

        app._run_palette_command("open 1")
        await pilot.pause()
        app.action_cycle_link_filter()
        app.link_relation_filter = "all"
        app._update_links_panel()
        app.action_next_link()
        app.action_prev_link()
        app.action_open_link_target()
        await pilot.pause()
        assert "Opened linked entry" in _status(app)

        app._current_links = [{"target": "bad", "relation": "references", "note": ""}]
        app._current_link_cursor = 0
        app.action_open_link_target()
        await pilot.pause()
        assert "Invalid link target" in _status(app)

        app.action_toggle_archive()
        await pilot.pause()
        assert "archived" in _status(app) or "restored" in _status(app)
        app._run_palette_command("archive")
        app._run_palette_command("restore")
        await pilot.pause()

        app._run_palette_command("open 1")
        app.action_edit_document()
        await pilot.pause()
        app.action_focus_search()
        app.action_focus_jump()
        app.action_cycle_link_filter()
        app.action_open_palette()
        app.action_toggle_archive()
        await pilot.pause()

        app.query_one("#doc-edit-label", Input).value = "Doc Updated"
        app.query_one("#doc-edit-file-type", Input).value = "txt"
        app.query_one("#doc-edit-tags", Input).value = "a,b"
        if len(app.query("#doc-edit-content")) > 0:
            area = app.query_one("#doc-edit-content")
            if hasattr(area, "load_text"):
                area.load_text("new-content")
            else:
                area.text = "new-content"
        else:
            app.query_one("#doc-edit-content-single", Input).value = "new-content"

        app.on_input_changed(
            SimpleNamespace(input=SimpleNamespace(id="doc-edit-label"))
        )
        app.on_text_area_changed(None)
        app.action_save_document()
        await pilot.pause()
        assert "Saved document" in _status(app)

        app._run_palette_command("open 1")
        app.action_edit_document()
        await pilot.pause()
        app.action_save_document()
        await pilot.pause()
        assert "No document changes to save" in _status(app)
        app.action_cancel_document_edit()
        await pilot.pause()

        app.on_input_submitted(
            SimpleNamespace(input=SimpleNamespace(id="quick-jump"), value="")
        )
        app.on_input_submitted(
            SimpleNamespace(input=SimpleNamespace(id="quick-jump"), value="x")
        )
        app.on_input_submitted(
            SimpleNamespace(input=SimpleNamespace(id="quick-jump"), value="2")
        )
        app.on_input_submitted(
            SimpleNamespace(input=SimpleNamespace(id="search"), value="Doc One")
        )
        app.on_input_submitted(
            SimpleNamespace(input=SimpleNamespace(id="command-palette"), value="help")
        )
        await pilot.pause()

        app._run_palette_command("filter all")
        app._run_palette_command("search Doc")
        await pilot.pause()
        first = app.query_one("#entry-list", ListView).children[0]
        app.on_list_view_selected(SimpleNamespace(item=first))
        await pilot.pause()

        app._run_palette_command("retry")
        await pilot.pause()


@pytest.mark.anyio
async def test_tui2_matrix_failure_paths_and_retry() -> None:
    svc = MatrixEntryService(
        [
            {"id": 1, "kind": "document", "label": "Doc", "content": "x"},
            {"id": 2, "kind": "password", "label": "Pw"},
        ],
        fail_links=True,
        fail_archive=True,
        fail_modify=True,
        fail_add_link=True,
        fail_remove_link=True,
    )
    app = _build_app(service=svc)
    async with app.run_test() as pilot:
        await pilot.pause()
        app._show_entry(1)
        await pilot.pause()
        assert "Links unavailable:" in str(app.query_one("#link-detail").render())

        app.action_retry_last_error()
        await pilot.pause()
        assert "retry" in _status(app).lower() or "failed" in _status(app).lower()

        app._run_palette_command("link-add 2 references nope")
        await pilot.pause()
        assert "link-add failed" in _status(app)

        app._run_palette_command("link-rm 2 references")
        await pilot.pause()
        assert "link-rm failed" in _status(app)

        app.action_toggle_archive()
        await pilot.pause()
        assert "Archive/restore failed" in _status(app)

        app.action_edit_document()
        await pilot.pause()
        app.query_one("#doc-edit-label", Input).value = "Doc2"
        app.action_save_document()
        await pilot.pause()
        assert "Failed to save document" in _status(app)
