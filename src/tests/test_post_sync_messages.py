import sys
from types import SimpleNamespace
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

import main


def test_handle_post_success(capsys):
    pm = SimpleNamespace(
        sync_vault=lambda alt_summary=None: "abcd",
    )
    main.handle_post_to_nostr(pm)
    out = capsys.readouterr().out
    assert "✅ Sync complete." in out
    assert "abcd" in out


def test_handle_post_failure(capsys):
    pm = SimpleNamespace(
        sync_vault=lambda alt_summary=None: None,
    )
    main.handle_post_to_nostr(pm)
    out = capsys.readouterr().out
    assert "❌ Sync failed…" in out
