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
        self.mode = "keyword"

    def set_semantic_index_enabled(self, enabled: bool) -> None:
        self.enabled = bool(enabled)

    def get_semantic_index_enabled(self) -> bool:
        return bool(self.enabled)

    def set_semantic_search_mode(self, mode: str) -> None:
        self.mode = str(mode)

    def get_semantic_search_mode(self) -> str:
        return str(self.mode)


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

    service.set_mode("semantic")
    semantic_only = service.search("agent", k=3, mode="semantic")
    assert len(semantic_only) >= 1

    service.set_mode("keyword")
    keyword_only = service.search("agent", k=3, mode="keyword")
    assert len(keyword_only) >= 1

    hybrid = service.search("agent", k=3, mode="hybrid")
    assert len(hybrid) >= 1


def test_stored_secrets_are_never_written_to_the_index(tmp_path):
    """The index is a plaintext file; secrets must not be in it.

    `_extract_text` used to append a key_value entry's `value` -- the stored
    secret itself -- which `build()` then wrote to
    semantic_index/records.json in the clear, alongside a tokenized copy that
    leaked it just as thoroughly. Nobody searches for a secret they do not
    already know, so indexing it was pure downside: it handed the value to
    anything that could read the profile directory (a backup, a sync client,
    another user on a shared machine) without the master password.
    """
    from seedpass.core.semantic_index import SemanticIndex

    index = SemanticIndex(tmp_path)
    index.build(
        [
            {
                "id": 1,
                "kind": "key_value",
                "label": "api-token",
                "key": "DEPLOY_TOKEN",
                "value": "SUPER-SECRET-VALUE-12345",
                "notes": "production credentials",
                "tags": ["ops"],
            }
        ]
    )

    raw = (tmp_path / "semantic_index" / "records.json").read_text(encoding="utf-8")
    assert "SUPER-SECRET-VALUE-12345" not in raw
    # Tokenized fragments leak it just as well as the whole string.
    for fragment in ("super", "12345"):
        assert fragment not in raw.lower()

    # The entry is still findable by everything that is not the secret.
    assert index.search("token")
    assert index.search("production")
    assert "DEPLOY_TOKEN" in raw


def test_index_files_are_not_readable_by_other_users(tmp_path):
    """Every other file in a profile is 0600; these were created at the umask."""
    from seedpass.core.semantic_index import SemanticIndex

    index = SemanticIndex(tmp_path)
    index.set_enabled(True)
    index.build([{"id": 1, "kind": "document", "label": "notes", "content": "hello"}])
    for name in ("records.json", "manifest.json"):
        mode = (tmp_path / "semantic_index" / name).stat().st_mode & 0o777
        assert mode == 0o600, f"{name} is {oct(mode)}"


def test_model_id_marks_indexes_built_before_the_fix(tmp_path):
    """A stale index still contains secrets, so it has to be distinguishable."""
    from seedpass.core.semantic_index import SemanticIndex

    index = SemanticIndex(tmp_path)
    index.build([{"id": 1, "kind": "document", "label": "notes", "content": "hello"}])
    assert index.status()["model_id"] == "seedpass-token-overlap-v2"


def test_the_first_entry_a_profile_creates_is_searchable(tmp_path):
    """Entry 0 is a real entry, not a missing one.

    The check was `int(entry.get("id", 0) or 0) <= 0`, which conflated "no
    id" with "id 0" — and entry ids start at 0, so the first entry any user
    ever created was silently absent from every search result, with nothing
    to indicate why.
    """
    from seedpass.core.semantic_index import SemanticIndex

    index = SemanticIndex(tmp_path)
    index.build(
        [
            {"id": 0, "kind": "password", "label": "bank.example", "notes": "first"},
            {"id": 1, "kind": "password", "label": "forum.example", "notes": "second"},
        ]
    )
    assert [hit["entry_id"] for hit in index.search("bank")] == [0]
    assert [hit["entry_id"] for hit in index.search("forum")] == [1]


def test_entries_without_a_usable_id_are_still_skipped(tmp_path):
    """Which is what the old check was reaching for."""
    from seedpass.core.semantic_index import SemanticIndex

    index = SemanticIndex(tmp_path)
    index.build(
        [
            {"kind": "document", "label": "no id", "content": "text"},
            {"id": None, "kind": "document", "label": "null id", "content": "text"},
            {"id": "abc", "kind": "document", "label": "bad id", "content": "text"},
            {"id": -1, "kind": "document", "label": "negative", "content": "text"},
        ]
    )
    assert index.search("text") == []


def test_an_index_built_before_the_fix_is_deleted_on_first_touch(tmp_path):
    """A v1 index still holds plaintext secrets; the fix does not rewrite it.

    Leaving it on disk and reporting a version string in a status field is not
    a remedy. Deleting is safe -- the index is a derived cache, rebuilt from
    the vault in milliseconds.
    """
    import json

    from seedpass.core.semantic_index import SemanticIndex

    index = SemanticIndex(tmp_path)
    index.build([{"id": 1, "kind": "document", "label": "notes", "content": "hello"}])

    manifest_path = tmp_path / "semantic_index" / "manifest.json"
    records_path = tmp_path / "semantic_index" / "records.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["model_id"] = "seedpass-token-overlap-v1"
    manifest_path.write_text(json.dumps(manifest))
    records_path.write_text(
        json.dumps(
            [
                {
                    "entry_id": 1,
                    "kind": "key_value",
                    "label": "x",
                    "text": "LEAKED-SECRET",
                    "tokens": ["leaked", "secret"],
                }
            ]
        )
    )

    # Searching it must neither return the leaked content nor leave it there.
    assert index.search("leaked") == []
    assert not records_path.exists()
    assert not manifest_path.exists()
    assert index.status()["built"] is False


def test_an_unreadable_manifest_is_not_treated_as_stale(tmp_path):
    """"Cannot tell" must not mean "delete it"."""
    from seedpass.core.semantic_index import SemanticIndex

    index = SemanticIndex(tmp_path)
    index.build([{"id": 1, "kind": "document", "label": "notes", "content": "hello"}])
    (tmp_path / "semantic_index" / "manifest.json").write_text("{ not json")

    index.status()
    assert (tmp_path / "semantic_index" / "records.json").exists()
