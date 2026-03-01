from __future__ import annotations

from time import perf_counter
from types import SimpleNamespace

import pytest

pytest.importorskip("textual")
from textual.widgets import Input, ListView

from seedpass.tui_v2.app import launch_tui2


class LargeKbService:
    def __init__(self, rows: int) -> None:
        self._entries = {}
        for idx in range(1, rows + 1):
            kind = "document" if idx % 5 == 0 else "password"
            entry = {
                "id": idx,
                "kind": kind,
                "label": f"KB-{idx:06d}",
                "archived": False,
                "tags": [f"tag-{idx % 100:03d}", "kb"],
            }
            if kind == "document":
                entry["content"] = f"doc-{idx}"
                entry["file_type"] = "md"
            else:
                entry["length"] = 16
                entry["username"] = f"user-{idx}"
                entry["url"] = f"https://example/{idx}"
            self._entries[idx] = entry

    def search_entries(self, query: str, kinds: list[str] | None = None):
        q = (query or "").strip().lower()
        rows = []
        for idx in sorted(self._entries.keys()):
            entry = self._entries[idx]
            kind = str(entry.get("kind", "password"))
            if kinds and kind not in kinds:
                continue
            label = str(entry.get("label", ""))
            tags = [str(tag).lower() for tag in entry.get("tags", [])]
            if q and q not in label.lower() and not any(q in t for t in tags):
                continue
            rows.append(
                (
                    idx,
                    label,
                    entry.get("username"),
                    entry.get("url"),
                    bool(entry.get("archived", False)),
                    SimpleNamespace(value=kind),
                )
            )
        return rows

    def retrieve_entry(self, entry_id: int):
        return dict(self._entries.get(int(entry_id), {}))

    def get_links(self, entry_id: int):
        _ = entry_id
        return []

    def generate_password(self, length: int, entry_id: int) -> str:
        return f"pw-{entry_id}-{length}"


def _build_app(service: LargeKbService):
    holder: dict[str, object] = {}

    def _hook(app):
        holder["app"] = app

    launched = launch_tui2(entry_service_factory=lambda: service, app_hook=_hook)
    assert launched is True
    app = holder.get("app")
    assert app is not None
    return app


def _filters(app) -> str:
    return str(app.query_one("#filters").render())


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("rows", "max_seconds"),
    [
        (10000, 6.0),
        pytest.param(50000, 18.0, marks=pytest.mark.stress),
    ],
)
async def test_tui2_kb_large_index_navigation(rows: int, max_seconds: float) -> None:
    app = _build_app(LargeKbService(rows))

    async with app.run_test() as pilot:
        start = perf_counter()
        await pilot.pause()

        list_view = app.query_one("#entry-list", ListView)
        assert len(list_view.children) == 200
        assert "Page: 1/" in _filters(app)

        app.action_next_page()
        app.action_next_page()
        await pilot.pause()
        assert "Page: 3/" in _filters(app)

        app.query_one("#search", Input).value = f"KB-{rows:06d}"
        app._load_entries(query=f"KB-{rows:06d}", reset_page=True)
        await pilot.pause()
        assert len(list_view.children) == 1

        app._run_palette_command("filter document")
        await pilot.pause()
        app._run_palette_command("search tag-040")
        await pilot.pause()
        assert len(list_view.children) >= 1

        elapsed = perf_counter() - start
        assert (
            elapsed <= max_seconds
        ), f"TUI large-index interaction exceeded budget: {elapsed:.3f}s > {max_seconds:.3f}s"
