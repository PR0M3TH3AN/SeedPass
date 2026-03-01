import sys
from types import SimpleNamespace
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

import main


def test_handle_post_success(capsys):
    pm = SimpleNamespace(
        sync_vault=lambda alt_summary=None: {
            "manifest_id": "abcd",
            "chunk_ids": ["c1", "c2"],
            "delta_ids": ["d1"],
        },
    )
    main.handle_post_to_nostr(pm)
    out = capsys.readouterr().out
    assert "✅ Sync complete." in out
    assert "abcd" in out
    assert "c1" in out and "c2" in out and "d1" in out


def test_handle_post_failure(capsys):
    pm = SimpleNamespace(
        sync_vault=lambda alt_summary=None: None,
    )
    main.handle_post_to_nostr(pm)
    out = capsys.readouterr().out
    assert "❌ Sync failed…" in out


def test_handle_post_failure_shows_nostr_error(capsys):
    pm = SimpleNamespace(
        sync_vault=lambda alt_summary=None: None,
        nostr_client=SimpleNamespace(last_error="Manifest out of date"),
    )
    main.handle_post_to_nostr(pm)
    out = capsys.readouterr().out
    assert "❌ Sync failed… Manifest out of date" in out


def test_handle_post_failure_offline_mode_message(capsys):
    pm = SimpleNamespace(
        sync_vault=lambda alt_summary=None: None,
        offline_mode=True,
    )
    main.handle_post_to_nostr(pm)
    out = capsys.readouterr().out
    assert "Offline mode is enabled. Disable it in Settings to sync." in out


def test_handle_post_prints_all_ids(capsys):
    pm = SimpleNamespace(
        sync_vault=lambda alt_summary=None: {
            "manifest_id": "m1",
            "chunk_ids": ["c1", "c2"],
            "delta_ids": ["d1", "d2"],
        }
    )
    main.handle_post_to_nostr(pm)
    out_lines = capsys.readouterr().out.splitlines()
    expected = [
        "  manifest: m1",
        "  chunk: c1",
        "  chunk: c2",
        "  delta: d1",
        "  delta: d2",
    ]
    for line in expected:
        assert any(line in ol for ol in out_lines)
