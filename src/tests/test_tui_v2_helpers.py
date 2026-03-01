from __future__ import annotations

import pytest

from seedpass.tui_v2.app import (
    pagination_window,
    parse_palette_command,
    truncate_entry_for_display,
)


def test_parse_palette_command_ok() -> None:
    cmd, args = parse_palette_command('link-add 42 related_to "note text"')
    assert cmd == "link-add"
    assert args == ["42", "related_to", "note text"]


def test_parse_palette_command_empty() -> None:
    with pytest.raises(ValueError, match="command required"):
        parse_palette_command("   ")


def test_parse_palette_command_unbalanced_quotes() -> None:
    with pytest.raises(ValueError, match="Palette parse error"):
        parse_palette_command('search "oops')


def test_pagination_window_normalizes_page() -> None:
    page, start, end, total_pages = pagination_window(
        total_rows=501, page_size=200, page_index=99
    )
    assert total_pages == 3
    assert page == 2
    assert start == 400
    assert end == 501


def test_pagination_window_empty() -> None:
    page, start, end, total_pages = pagination_window(
        total_rows=0, page_size=200, page_index=5
    )
    assert total_pages == 1
    assert page == 0
    assert start == 0
    assert end == 0


def test_pagination_window_rejects_nonpositive_page_size() -> None:
    with pytest.raises(ValueError, match="page_size"):
        pagination_window(total_rows=10, page_size=0, page_index=0)


def test_truncate_entry_for_display_no_content() -> None:
    payload = truncate_entry_for_display({"kind": "password", "label": "x"}, 10)
    assert payload == {"kind": "password", "label": "x"}


def test_truncate_entry_for_display_truncates_content() -> None:
    payload = truncate_entry_for_display({"content": "A" * 25, "kind": "document"}, 10)
    assert payload["content"].startswith("A" * 10)
    assert payload["content_truncated"] is True


@pytest.mark.parametrize("rows", [1000, 10000, 50000])
def test_pagination_window_large_vault_sizes(rows: int) -> None:
    # Large-vault smoke: pagination math remains stable at high row counts.
    last_page = (rows - 1) // 200 if rows else 0
    page, start, end, total_pages = pagination_window(
        total_rows=rows, page_size=200, page_index=last_page
    )
    assert page == last_page
    assert total_pages >= 1
    assert 0 <= start <= end <= rows
