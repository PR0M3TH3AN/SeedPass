from __future__ import annotations

import pytest

from seedpass.tui_v2.app import (
    pagination_window,
    parse_palette_command,
    render_qr_ascii,
    split_palette_args,
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


def test_render_qr_ascii_nonempty() -> None:
    rendered = render_qr_ascii("otpauth://totp/example?secret=JBSWY3DPEHPK3PXP")
    lines = [line for line in rendered.splitlines() if line.strip()]
    assert len(lines) > 4
    assert any("##" in line for line in lines)


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


class TestSplitPaletteArgs:
    """Both platform branches, tested from either platform.

    `windows` is an explicit parameter rather than a bare `os.name` check
    precisely so these can run everywhere. Without that, the Windows branch
    would only ever be exercised on Windows — which is how the bug below
    survived: shlex.split defaults to POSIX mode, where backslash is an ESCAPE
    character, so every Windows path a user typed came back with its
    separators eaten and doc-export, export-field, db-export, db-import and
    parent-seed-backup wrote nowhere while reporting success.
    """

    def test_windows_paths_keep_their_separators(self) -> None:
        assert split_palette_args(
            r"doc-export C:\Users\me\Temp\exports", windows=True
        ) == ["doc-export", r"C:\Users\me\Temp\exports"]

    def test_posix_mode_would_have_eaten_them(self) -> None:
        # The bug, pinned. If someone "simplifies" the helper back to a plain
        # shlex.split, this is what Windows users get.
        assert split_palette_args(
            r"doc-export C:\Users\me\Temp\exports", windows=False
        ) == ["doc-export", "C:UsersmeTempexports"]

    def test_quoted_windows_paths_survive_with_quotes_removed(self) -> None:
        # Non-POSIX shlex keeps the quotes on the token; they have to come off
        # or the path gains a literal quote character.
        assert split_palette_args(
            'db-export "C:\\Program Files\\out.enc"', windows=True
        ) == ["db-export", r"C:\Program Files\out.enc"]

    def test_posix_behaviour_is_unchanged(self) -> None:
        assert split_palette_args("doc-export /tmp/exports", windows=False) == [
            "doc-export",
            "/tmp/exports",
        ]
        assert split_palette_args('db-export "/tmp/with space.enc"', windows=False) == [
            "db-export",
            "/tmp/with space.enc",
        ]

    def test_quoting_still_groups_on_windows(self) -> None:
        assert split_palette_args(
            'link-add 42 related_to "note text"', windows=True
        ) == [
            "link-add",
            "42",
            "related_to",
            "note text",
        ]
