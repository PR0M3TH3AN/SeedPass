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


def _status_text(app) -> str:
    return str(app.query_one("#status", Static).renderable)


def _filters_text(app) -> str:
    return str(app.query_one("#filters", Static).renderable)


async def _run_palette(pilot, command: str) -> None:
    await pilot.press("ctrl+p")
    await pilot.type(command)
    await pilot.press("enter")
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

        await pilot.press("n")
        await pilot.pause()
        assert "Page: 2/3" in _filters_text(app)

        await pilot.press("/")
        await pilot.type("Entry 44")
        await pilot.press("enter")
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
        await pilot.press("e")
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

        await pilot.press("ctrl+s")
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

        await _run_palette(pilot, "link-add 2 references rel-note")
        links_text = str(app.query_one("#link-detail", Static).renderable)
        assert "references -> 2 (rel-note)" in links_text

        await pilot.press("o")
        await pilot.pause()
        assert "Opened linked entry 2" in _status_text(app)

        await _run_palette(pilot, "link-rm 2 references")
        links_text = str(app.query_one("#link-detail", Static).renderable)
        assert "No graph links" in links_text


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

        await pilot.press("x")
        await pilot.pause()

        list_view = app.query_one("#entry-list", ListView)
        assert len(list_view.children) == 1
        assert "retry" not in _status_text(app).lower()
