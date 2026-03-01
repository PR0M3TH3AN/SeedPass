from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter

import pytest

from helpers import TEST_PASSWORD, TEST_SEED, create_vault
from seedpass.core.backup import BackupManager
from seedpass.core.config_manager import ConfigManager
from seedpass.core.entry_management import EntryManager
from seedpass.core.entry_types import EntryType


def _entry_manager(tmp_path: Path) -> EntryManager:
    vault, _ = create_vault(tmp_path, TEST_SEED, TEST_PASSWORD)
    cfg_mgr = ConfigManager(vault, tmp_path)
    backup_mgr = BackupManager(tmp_path, cfg_mgr)
    return EntryManager(vault, backup_mgr)


def _seed_bulk_entries(em: EntryManager, rows: int) -> None:
    data = em._load_index(force_reload=True)
    entries: dict[str, dict] = {}
    for idx in range(rows):
        label = f"KB-ENTRY-{idx:06d}"
        tags = [f"tag-{idx % 100:03d}", "kb", "ops"]
        if idx % 5 == 0:
            entries[str(idx)] = {
                "type": EntryType.DOCUMENT.value,
                "kind": EntryType.DOCUMENT.value,
                "label": label,
                "content": f"doc-content-{idx}",
                "file_type": "md",
                "tags": tags,
                "notes": "",
                "links": [],
                "archived": False,
                "modified_ts": idx,
            }
        else:
            entries[str(idx)] = {
                "type": EntryType.PASSWORD.value,
                "kind": EntryType.PASSWORD.value,
                "label": label,
                "username": f"user-{idx}",
                "url": f"https://example/{idx}",
                "length": 16,
                "tags": tags,
                "notes": "",
                "links": [],
                "archived": False,
                "modified_ts": idx,
            }
    data["entries"] = entries
    em._save_index(data)


@pytest.mark.parametrize(
    ("rows", "max_seconds"),
    [
        (10000, 10.0),
        pytest.param(100000, 60.0, marks=pytest.mark.stress),
    ],
)
def test_kb_sort_tag_search_scale(rows: int, max_seconds: float) -> None:
    with TemporaryDirectory() as tmpdir:
        em = _entry_manager(Path(tmpdir))
        _seed_bulk_entries(em, rows)

        start = perf_counter()
        by_label = em.list_entries(sort_by="label", verbose=False)
        by_updated = em.list_entries(sort_by="updated", verbose=False)
        tag_hits = em.search_entries("tag-042")
        label_hits = em.search_entries(f"KB-ENTRY-{rows - 1:06d}")
        elapsed = perf_counter() - start

        assert len(by_label) == rows
        assert by_label[0][1] == "KB-ENTRY-000000"
        assert by_label[-1][1] == f"KB-ENTRY-{rows - 1:06d}"

        assert len(by_updated) == rows
        assert by_updated[0][0] == rows - 1
        assert by_updated[-1][0] == 0

        expected_tag_hits = rows // 100 + (1 if rows % 100 > 42 else 0)
        assert len(tag_hits) == expected_tag_hits
        assert label_hits == [
            (
                rows - 1,
                f"KB-ENTRY-{rows - 1:06d}",
                f"user-{rows - 1}",
                f"https://example/{rows - 1}",
                False,
                EntryType.PASSWORD,
            )
        ] or label_hits == [
            (
                rows - 1,
                f"KB-ENTRY-{rows - 1:06d}",
                None,
                None,
                False,
                EntryType.DOCUMENT,
            )
        ]
        assert (
            elapsed <= max_seconds
        ), f"KB scale sort/search exceeded budget: {elapsed:.3f}s > {max_seconds:.3f}s"


@pytest.mark.parametrize(
    ("degree", "max_seconds"),
    [
        (1000, 6.0),
        pytest.param(5000, 30.0, marks=pytest.mark.stress),
    ],
)
def test_kb_graph_high_degree_links_scale(degree: int, max_seconds: float) -> None:
    with TemporaryDirectory() as tmpdir:
        em = _entry_manager(Path(tmpdir))
        data = em._load_index(force_reload=True)
        entries: dict[str, dict] = {
            "0": {
                "type": EntryType.DOCUMENT.value,
                "kind": EntryType.DOCUMENT.value,
                "label": "KB Root",
                "content": "root",
                "file_type": "md",
                "tags": ["kb", "graph"],
                "links": [],
                "archived": False,
                "modified_ts": 0,
            }
        }
        for i in range(1, degree + 1):
            entries[str(i)] = {
                "type": EntryType.KEY_VALUE.value,
                "kind": EntryType.KEY_VALUE.value,
                "label": f"Node-{i:05d}",
                "key": f"k{i}",
                "value": f"v{i}",
                "tags": [f"group-{i % 10}"],
                "links": [],
                "archived": False,
                "modified_ts": i,
            }
        entries["0"]["links"] = [
            {
                "target_id": i,
                "relation": "depends_on" if i % 2 else "references",
                "note": f"edge-{i}",
            }
            for i in range(1, degree + 1)
        ]
        data["entries"] = entries
        em._save_index(data)

        start = perf_counter()
        resolved = em.get_links(0)
        relation_hits = em.search_entries("depends_on")
        target_hits = em.search_entries(f"Node-{degree:05d}")
        target_depends_on = degree if degree % 2 else degree - 1
        remaining = em.remove_link(0, target_depends_on, relation="depends_on")
        elapsed = perf_counter() - start

        assert len(resolved) == degree
        assert resolved[0]["target_label"].startswith("Node-")
        assert resolved[0]["target_kind"] == EntryType.KEY_VALUE.value
        assert relation_hits and relation_hits[0][0] == 0
        assert target_hits and target_hits[0][0] == 0
        assert len(remaining) == degree - 1
        assert (
            elapsed <= max_seconds
        ), f"KB graph high-degree operations exceeded budget: {elapsed:.3f}s > {max_seconds:.3f}s"
