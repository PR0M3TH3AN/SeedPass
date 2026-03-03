from __future__ import annotations

from types import SimpleNamespace

import pytest

pytest.importorskip("textual")
from textual.widgets import DataTable

from seedpass.tui_v3 import launch_tui3


class V3EntryService:
    def __init__(self) -> None:
        self._entries: dict[int, dict] = {
            1: {"id": 1, "kind": "password", "label": "Email", "length": 16},
            2: {"id": 2, "kind": "managed_account", "label": "Managed Ops"},
            3: {"id": 3, "kind": "nostr", "label": "Agent Nostr"},
        }
        self.copied: list[str] = []

    def search_entries(
        self,
        query: str,
        kinds: list[str] | None = None,
        *,
        include_archived: bool = False,
        archived_only: bool = False,
    ):
        _ = (include_archived, archived_only)
        q = (query or "").strip().lower()
        rows = []
        for entry_id in sorted(self._entries.keys()):
            entry = self._entries[entry_id]
            kind = str(entry.get("kind", "password"))
            if kinds and kind not in kinds:
                continue
            label = str(entry.get("label", ""))
            if q and q not in label.lower():
                continue
            rows.append(
                (
                    entry_id,
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

    def generate_password(self, length: int, entry_id: int) -> str:
        return f"pw-{entry_id}-{length}"

    def archive_entry(self, entry_id: int) -> None:
        self._entries[int(entry_id)]["archived"] = True

    def restore_entry(self, entry_id: int) -> None:
        self._entries[int(entry_id)]["archived"] = False

    def copy_to_clipboard(self, value: str) -> bool:
        self.copied.append(value)
        return True


class V3ProfileService:
    def list_profiles(self) -> list[str]:
        return ["EFBE51E70ED1B53A"]


class V3VaultService:
    def __init__(self) -> None:
        self.locked = False
        self.last_unlock_password: str | None = None
        self._manager = SimpleNamespace(parent_seed="PARENT_SEED")

    def lock(self) -> None:
        self.locked = True

    def unlock(self, request) -> SimpleNamespace:
        if hasattr(request, "password"):
            self.last_unlock_password = str(request.password)
        else:
            self.last_unlock_password = str(request)
        self.locked = False
        return SimpleNamespace(status="ok", duration=0.01)

    def stats(self) -> dict[str, int]:
        return {"total_entries": 3}


def _build_app() -> tuple[object, V3EntryService, V3VaultService]:
    holder: dict[str, object] = {}
    entry = V3EntryService()
    vault = V3VaultService()
    profile = V3ProfileService()

    def _hook(app):
        holder["app"] = app

    launched = launch_tui3(
        fingerprint="EFBE51E70ED1B53A",
        entry_service_factory=lambda: entry,
        profile_service_factory=lambda: profile,
        vault_service_factory=lambda: vault,
        app_hook=_hook,
    )
    assert launched is True
    app = holder.get("app")
    assert app is not None
    return app, entry, vault


@pytest.mark.anyio
async def test_tui3_palette_lock_unlock_and_session_status() -> None:
    app, _entry, vault = _build_app()
    async with app.run_test() as pilot:
        await pilot.pause()
        assert app.session_locked is False
        app.processor.execute("session-status")
        app.processor.execute("lock")
        await pilot.pause()
        assert app.session_locked is True
        assert vault.locked is True
        app.processor.execute("unlock hunter2")
        await pilot.pause()
        assert app.session_locked is False
        assert vault.locked is False
        assert vault.last_unlock_password == "hunter2"


@pytest.mark.anyio
async def test_tui3_sidebar_child_nodes_open_entries() -> None:
    app, _entry, _vault = _build_app()
    async with app.run_test() as pilot:
        await pilot.pause()
        tree = app.screen.query_one("#profile-tree")
        tree.on_tree_node_selected(
            SimpleNamespace(node=SimpleNamespace(data="managed:2"))
        )
        await pilot.pause()
        assert app.selected_entry_id == 2
        assert app.active_fingerprint == "EFBE51E70ED1B53A"
        tree.on_tree_node_selected(
            SimpleNamespace(node=SimpleNamespace(data="agent:3"))
        )
        await pilot.pause()
        assert app.selected_entry_id == 3


@pytest.mark.anyio
async def test_tui3_grid_focus_refresh_enables_selection_after_runtime_add() -> None:
    app, entry, _vault = _build_app()
    async with app.run_test() as pilot:
        await pilot.pause()
        entry._entries[4] = {
            "id": 4,
            "kind": "password",
            "label": "Runtime Added",
            "length": 18,
        }
        table = app.screen.query_one("#entry-data-table", DataTable)
        table.focus()
        await pilot.pause()
        table._refresh_data()
        await pilot.pause()
        assert table.row_count >= 4
