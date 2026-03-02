from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from seedpass.core.semantic_index import SemanticIndex
from seedpass.core.api import SemanticIndexService


def test_semantic_index_build_and_search(tmp_path: Path) -> None:
    idx = SemanticIndex(tmp_path)
    assert idx.status()["built"] is False

    idx.set_enabled(True)
    payload = idx.build(
        [
            {
                "id": 1,
                "kind": "document",
                "label": "Runbook",
                "content": "Nostr relay recovery process and checklist",
                "tags": ["ops", "relay"],
            },
            {
                "id": 2,
                "kind": "password",
                "label": "GitHub",
                "username": "alice",
                "url": "https://github.com",
            },
            {
                "id": 3,
                "kind": "seed",
                "label": "Seed",
                "seed_phrase": "abandon " * 11 + "about",
            },
        ]
    )
    assert payload["built"] is True
    assert payload["enabled"] is True
    assert payload["records"] == 2

    results = idx.search("relay checklist", k=5)
    assert len(results) >= 1
    assert results[0]["entry_id"] == 1
    assert "Runbook" in results[0]["label"]


class _DummyConfig:
    def __init__(self) -> None:
        self.enabled = False

    def set_semantic_index_enabled(self, enabled: bool) -> None:
        self.enabled = bool(enabled)

    def get_semantic_index_enabled(self) -> bool:
        return bool(self.enabled)


class _DummyEntryManager:
    def __init__(self) -> None:
        self._entries = {
            1: {
                "id": 1,
                "kind": "document",
                "label": "Doc",
                "content": "agent context",
            },
            2: {
                "id": 2,
                "kind": "key_value",
                "label": "Env",
                "key": "REGION",
                "value": "us-east",
            },
        }

    def search_entries(self, *_args, **_kwargs):
        return [
            (1, "Doc", None, None, False, SimpleNamespace(value="document")),
            (2, "Env", None, None, False, SimpleNamespace(value="key_value")),
        ]

    def retrieve_entry(self, entry_id: int):
        return dict(self._entries[int(entry_id)])


def test_semantic_index_service_build_and_status(tmp_path: Path) -> None:
    manager = SimpleNamespace(
        fingerprint_dir=tmp_path,
        config_manager=_DummyConfig(),
        entry_manager=_DummyEntryManager(),
    )
    service = SemanticIndexService(manager)
    status = service.status()
    assert status["enabled"] is False
    assert status["built"] is False

    enabled = service.set_enabled(True)
    assert enabled["enabled"] is True

    built = service.build()
    assert built["built"] is True
    assert built["records"] == 2

    results = service.search("agent", k=3)
    assert len(results) >= 1
    assert results[0]["entry_id"] == 1
