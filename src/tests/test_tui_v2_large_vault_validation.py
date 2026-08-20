from __future__ import annotations

from time import perf_counter

import pytest

from seedpass.tui_v2.app import pagination_window, truncate_entry_for_display


def _deterministic_labels(rows: int) -> list[str]:
    return [f"Entry-{i:06d}" for i in range(rows)]


@pytest.mark.parametrize(
    ("rows", "max_seconds"),
    [
        (10000, 2.0),
        pytest.param(50000, 8.0, marks=pytest.mark.stress),
    ],
)
def test_large_vault_pagination_validation(rows: int, max_seconds: float) -> None:
    """CI-like pagination scan over deterministic large-vault datasets."""
    labels = _deterministic_labels(rows)

    start = perf_counter()
    total_seen = 0
    page = 0
    seen_first = None
    seen_last = None
    while True:
        page, start_idx, end_idx, total_pages = pagination_window(rows, 200, page)
        if start_idx >= end_idx:
            break
        batch = labels[start_idx:end_idx]
        assert len(batch) <= 200
        if seen_first is None:
            seen_first = batch[0]
        seen_last = batch[-1]
        total_seen += len(batch)
        if page >= total_pages - 1:
            break
        page += 1

    elapsed = perf_counter() - start

    assert total_seen == rows
    assert seen_first == "Entry-000000"
    assert seen_last == f"Entry-{rows - 1:06d}"
    assert (
        elapsed <= max_seconds
    ), f"Large-vault pagination scan exceeded budget: {elapsed:.3f}s > {max_seconds:.3f}s"


@pytest.mark.parametrize(
    ("content_size", "limit", "expected_truncated"),
    [
        (4096, 4000, True),
        (1000, 4000, False),
        pytest.param(200000, 4000, True, marks=pytest.mark.stress),
    ],
)
def test_large_document_detail_truncation_validation(
    content_size: int, limit: int, expected_truncated: bool
) -> None:
    """Ensure large document previews remain bounded and deterministic."""
    payload = truncate_entry_for_display(
        {
            "kind": "document",
            "label": "Big Doc",
            "content": "X" * content_size,
        },
        limit,
    )

    assert payload["label"] == "Big Doc"
    assert payload["kind"] == "document"
    assert ("content_truncated" in payload) is expected_truncated
    if expected_truncated:
        assert payload["content"].startswith("X" * limit)
        assert "truncated" in payload["content"]
    else:
        assert payload["content"] == "X" * content_size
