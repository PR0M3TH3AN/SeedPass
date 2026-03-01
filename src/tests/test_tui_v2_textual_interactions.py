from __future__ import annotations

from types import SimpleNamespace

import pytest

pytest.importorskip("textual")
from textual.widgets import Input, ListView, Static

from seedpass.tui_v2.app import launch_tui2


class FakeEntryService:
    def __init__(self, entries: list[dict], *, fail_search_times: int = 0) -> None:
        self._entries = {int(entry["id"]): dict(entry) for entry in entries}
        self._links = {
            int(entry["id"]): [dict(link) for link in entry.get("links", [])]
            for entry in entries
        }
        self.fail_search_times = fail_search_times
        self.secret_mode_enabled = False
        self.clipboard_delay = 30
        self.clipboard_values: list[str] = []

    def search_entries(self, query: str, kinds: list[str] | None = None):
        if self.fail_search_times > 0:
            self.fail_search_times -= 1
            raise RuntimeError("temporary search failure")

        q = (query or "").strip().lower()
        out = []
        for entry_id in sorted(self._entries.keys()):
            entry = self._entries[entry_id]
            kind = str(entry.get("kind", "password"))
            if kinds and kind not in kinds:
                continue
            label = str(entry.get("label", ""))
            if q and q not in label.lower():
                continue
            out.append(
                (
                    entry_id,
                    label,
                    None,
                    None,
                    bool(entry.get("archived", False)),
                    SimpleNamespace(value=kind),
                )
            )
        return out

    def retrieve_entry(self, entry_id: int):
        return dict(self._entries.get(int(entry_id), {}))

    def modify_entry(self, entry_id: int, **kwargs) -> None:
        entry = self._entries[int(entry_id)]
        for key, value in kwargs.items():
            if value is None:
                continue
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
        self._entries[int(entry_id)]["archived"] = True

    def restore_entry(self, entry_id: int) -> None:
        self._entries[int(entry_id)]["archived"] = False

    def get_links(self, entry_id: int):
        return [dict(link) for link in self._links.get(int(entry_id), [])]

    def add_link(
        self,
        entry_id: int,
        target_id: int,
        *,
        relation: str = "related_to",
        note: str = "",
    ):
        links = self._links.setdefault(int(entry_id), [])
        links.append(
            {
                "target": int(target_id),
                "relation": relation,
                "note": note,
            }
        )
        return [dict(link) for link in links]

    def remove_link(
        self, entry_id: int, target_id: int, *, relation: str | None = None
    ):
        src = self._links.setdefault(int(entry_id), [])
        kept = []
        for link in src:
            if int(link.get("target", -1)) != int(target_id):
                kept.append(link)
                continue
            if relation is not None and str(link.get("relation")) != relation:
                kept.append(link)
        self._links[int(entry_id)] = kept
        return [dict(link) for link in kept]


def _build_app(service: FakeEntryService):
    holder: dict[str, object] = {}

    def _hook(app):
        holder["app"] = app

    launched = launch_tui2(entry_service_factory=lambda: service, app_hook=_hook)
    assert launched is True
    app = holder.get("app")
    assert app is not None
    return app


def _widget_text(app, selector: str) -> str:
    return str(app.query_one(selector).render())


def _status_text(app) -> str:
    return _widget_text(app, "#status")


def _filters_text(app) -> str:
    return _widget_text(app, "#filters")


async def _run_palette(app, pilot, command: str) -> None:
    app.action_open_palette()
    await pilot.pause()
    app._run_palette_command(command)
    app._set_palette_visible(False)
    await pilot.pause()


@pytest.mark.anyio
async def test_tui2_textual_pagination_and_search_flow() -> None:
    entries = [
        {"id": i, "kind": "document", "label": f"Entry {i}", "content": "x"}
        for i in range(1, 451)
    ]
    app = _build_app(FakeEntryService(entries))

    async with app.run_test() as pilot:
        await pilot.pause()
        list_view = app.query_one("#entry-list", ListView)
        assert len(list_view.children) == 200
        assert "Page: 1/3" in _filters_text(app)

        app.action_next_page()
        await pilot.pause()
        assert "Page: 2/3" in _filters_text(app)

        app.query_one("#search", Input).value = "Entry 44"
        app._load_entries(query="Entry 44", reset_page=True)
        await pilot.pause()
        assert len(list_view.children) == 11
        assert "Page: 1/1" in _filters_text(app)


@pytest.mark.anyio
async def test_tui2_textual_document_edit_save_flow() -> None:
    service = FakeEntryService(
        [
            {
                "id": 1,
                "kind": "document",
                "label": "Doc A",
                "content": "hello",
                "file_type": "txt",
                "tags": ["alpha"],
            }
        ]
    )
    app = _build_app(service)

    async with app.run_test() as pilot:
        await pilot.pause()
        app.action_edit_document()
        await pilot.pause()

        app.query_one("#doc-edit-label", Input).value = "Doc A Updated"
        app.query_one("#doc-edit-file-type", Input).value = "md"
        app.query_one("#doc-edit-tags", Input).value = "alpha, beta"
        if len(app.query("#doc-edit-content")) > 0:
            area = app.query_one("#doc-edit-content")
            if hasattr(area, "load_text"):
                area.load_text("new content")
            else:
                area.text = "new content"
        else:
            app.query_one("#doc-edit-content-single", Input).value = "new content"

        app.action_save_document()
        await pilot.pause()

        entry = service.retrieve_entry(1)
        assert entry["label"] == "Doc A Updated"
        assert entry["file_type"] == "md"
        assert entry["tags"] == ["alpha", "beta"]
        assert "Saved document 1" in _status_text(app)


@pytest.mark.anyio
async def test_tui2_textual_link_commands_and_neighbor_open() -> None:
    service = FakeEntryService(
        [
            {"id": 1, "kind": "document", "label": "Doc 1", "content": "a"},
            {"id": 2, "kind": "password", "label": "Login 2"},
        ]
    )
    app = _build_app(service)

    async with app.run_test() as pilot:
        await pilot.pause()

        await _run_palette(app, pilot, "link-add 2 references rel-note")
        links_text = _widget_text(app, "#link-detail")
        assert "references -> 2 (rel-note)" in links_text

        app.action_open_link_target()
        await pilot.pause()
        assert "Opened linked entry 2" in _status_text(app)

        await _run_palette(app, pilot, "link-rm 2 references")
        links_text = _widget_text(app, "#link-detail")
        assert "No graph links" in links_text


@pytest.mark.anyio
async def test_tui2_textual_reveal_and_qr_flow() -> None:
    service = FakeEntryService(
        [
            {"id": 1, "kind": "password", "label": "Login 1", "length": 16},
            {
                "id": 2,
                "kind": "seed",
                "label": "Seed 2",
                "seed_phrase": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            },
            {
                "id": 3,
                "kind": "totp",
                "label": "TOTP 3",
                "secret": "JBSWY3DPEHPK3PXP",
                "period": 30,
                "digits": 6,
            },
        ]
    )
    app = _build_app(service)

    async with app.run_test() as pilot:
        await pilot.pause()

        app._run_palette_command("open 1")
        app.action_reveal_selected()
        await pilot.pause()
        assert "Password : pw-1-16" in _widget_text(app, "#secret-detail")

        app._run_palette_command("open 2")
        app.action_show_qr()
        await pilot.pause()
        qr_text = _widget_text(app, "#secret-detail")
        assert "Seed #2 QR" in qr_text
        assert "Payload:" in qr_text

        app._run_palette_command("open 3")
        app._run_palette_command("reveal")
        await pilot.pause()
        assert "Secret : JBSWY3DPEHPK3PXP" in _widget_text(app, "#secret-detail")

        app._run_palette_command("qr")
        await pilot.pause()
        assert "TOTP #3 QR" in _widget_text(app, "#secret-detail")


@pytest.mark.anyio
async def test_tui2_textual_sensitive_confirm_and_secret_mode_clipboard() -> None:
    service = FakeEntryService(
        [
            {
                "id": 1,
                "kind": "ssh",
                "label": "SSH 1",
                "private_key": "SSH_PRIVATE_1",
                "public_key": "ssh-ed25519 AAAA-1",
            },
            {
                "id": 2,
                "kind": "nostr",
                "label": "Nostr 2",
                "npub": "npub1abc",
                "nsec": "nsec1abc",
            },
        ]
    )
    service.secret_mode_enabled = True
    service.clipboard_delay = 45
    app = _build_app(service)

    async with app.run_test() as pilot:
        await pilot.pause()

        app._run_palette_command("open 1")
        app._run_palette_command("reveal")
        await pilot.pause()
        assert "requires confirmation" in _status_text(app)

        app._run_palette_command("reveal confirm")
        await pilot.pause()
        assert "copied to clipboard" in _widget_text(app, "#secret-detail")
        assert service.clipboard_values[-1] == "SSH_PRIVATE_1"

        app._run_palette_command("open 2")
        app._run_palette_command("qr private")
        await pilot.pause()
        assert "requires confirmation" in _status_text(app)

        app._run_palette_command("qr private confirm")
        await pilot.pause()
        assert "Nostr #2 QR" in _widget_text(app, "#secret-detail")


@pytest.mark.anyio
async def test_tui2_textual_retry_after_search_failure() -> None:
    service = FakeEntryService(
        [{"id": 1, "kind": "document", "label": "Doc 1", "content": "a"}],
        fail_search_times=1,
    )
    app = _build_app(service)

    async with app.run_test() as pilot:
        await pilot.pause()
        assert "Failed to load entries" in _status_text(app)

        app.action_retry_last_error()
        await pilot.pause()

        list_view = app.query_one("#entry-list", ListView)
        assert len(list_view.children) == 1
        assert "retry" not in _status_text(app).lower()
