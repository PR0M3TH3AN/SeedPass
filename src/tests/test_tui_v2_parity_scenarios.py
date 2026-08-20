from __future__ import annotations

from types import SimpleNamespace

import pytest

pytest.importorskip("textual")
from textual.widgets import ListView, Static

from seedpass.tui_v2.app import launch_tui2


class FakeEntryService:
    def __init__(self, entries: list[dict]) -> None:
        self._entries = {int(entry["id"]): dict(entry) for entry in entries}
        self._links = {
            int(entry["id"]): [dict(link) for link in entry.get("links", [])]
            for entry in entries
        }

    def search_entries(
        self,
        query: str,
        kinds: list[str] | None = None,
        *,
        include_archived: bool = False,
        archived_only: bool = False,
    ):
        q = (query or "").strip().lower()
        out = []
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
            out.append(
                (
                    entry_id,
                    label,
                    None,
                    None,
                    archived,
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
        links.append({"target": int(target_id), "relation": relation, "note": note})
        return [dict(link) for link in links]

    def remove_link(
        self, entry_id: int, target_id: int, *, relation: str | None = None
    ):
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


async def _run_palette(app, pilot, command: str) -> None:
    app.action_open_palette()
    await pilot.pause()
    app._run_palette_command(command)
    await pilot.pause()


def _status_text(app) -> str:
    return _widget_text(app, "#status")


@pytest.mark.anyio
async def test_tui2_parity_filters_cover_all_entry_kinds() -> None:
    kinds = [
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
    entries = [
        {"id": i + 1, "kind": kind, "label": f"{kind}-entry", "content": "x"}
        for i, kind in enumerate(kinds)
    ]
    app = _build_app(FakeEntryService(entries))

    async with app.run_test() as pilot:
        await pilot.pause()
        list_view = app.query_one("#entry-list", ListView)
        assert len(list_view.children) == len(kinds)

        for kind in kinds:
            await _run_palette(app, pilot, f"filter {kind}")
            assert len(list_view.children) == 1
            # Explicitly open the entry to ensure selection (parity requirement)
            entry_id = entries[kinds.index(kind)]["id"]
            await _run_palette(app, pilot, f"open {entry_id}")
            detail_text = _widget_text(app, "#entry-detail")
            assert kind in detail_text.lower()

        await _run_palette(app, pilot, "filter all")
        assert len(list_view.children) == len(kinds)


@pytest.mark.anyio
async def test_tui2_parity_archive_restore_roundtrip_non_document() -> None:
    service = FakeEntryService(
        [{"id": 1, "kind": "password", "label": "pw-entry", "archived": False}]
    )
    app = _build_app(service)

    async with app.run_test() as pilot:
        await pilot.pause()
        # Explicitly open the entry to ensure selection
        await _run_palette(app, pilot, "open 1")

        await _run_palette(app, pilot, "archive")
        assert service.retrieve_entry(1)["archived"] is True
        assert "archived" in _status_text(app)

        await _run_palette(app, pilot, "restore")
        assert service.retrieve_entry(1)["archived"] is False
        assert "restored" in _status_text(app)


@pytest.mark.anyio
async def test_tui2_parity_edit_document_guard_for_non_document() -> None:
    app = _build_app(FakeEntryService([{"id": 1, "kind": "password", "label": "pw"}]))

    async with app.run_test() as pilot:
        await pilot.pause()
        app.action_edit_document()
        await pilot.pause()
        assert "Select a document entry to edit" in _status_text(app)
