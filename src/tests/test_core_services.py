import types
from types import SimpleNamespace

from seedpass.core.api import VaultService, EntryService, SyncService, UnlockRequest
from seedpass.core.entry_types import EntryType


def test_vault_service_unlock():
    called = {}

    def unlock_vault(pw: str) -> float:
        called["pw"] = pw
        return 0.42

    pm = SimpleNamespace(unlock_vault=unlock_vault)
    service = VaultService(pm)
    resp = service.unlock(UnlockRequest(password="secret"))
    assert called["pw"] == "secret"
    assert resp.duration == 0.42


def test_entry_service_add_entry_and_search():
    called = {}

    def add_entry(label, length, username=None, url=None):
        called["add"] = (label, length, username, url)
        return 5

    def search_entries(q, kinds=None):
        called["search"] = (q, kinds)
        return [(5, "Example", username, url, False, EntryType.PASSWORD)]

    def start_background_vault_sync():
        called["sync"] = True

    username = "user"
    url = "https://ex.com"
    pm = SimpleNamespace(
        entry_manager=SimpleNamespace(
            add_entry=add_entry, search_entries=search_entries
        ),
        start_background_vault_sync=start_background_vault_sync,
    )
    service = EntryService(pm)
    idx = service.add_entry("Example", 12, username, url)
    assert idx == 5
    assert called["add"] == ("Example", 12, username, url)
    assert called.get("sync") is True

    results = service.search_entries("ex", kinds=["password"])
    assert results == [(5, "Example", username, url, False, EntryType.PASSWORD)]
    assert called["search"] == ("ex", ["password"])


def test_sync_service_sync():
    called = {}

    def sync_vault():
        called["sync"] = True
        return {
            "manifest_id": "m1",
            "chunk_ids": ["c1"],
            "delta_ids": ["d1"],
        }

    pm = SimpleNamespace(sync_vault=sync_vault)
    service = SyncService(pm)
    resp = service.sync()
    assert called["sync"] is True
    assert resp.manifest_id == "m1"
    assert resp.chunk_ids == ["c1"]
    assert resp.delta_ids == ["d1"]
