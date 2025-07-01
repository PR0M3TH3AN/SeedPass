import sys
from types import SimpleNamespace
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

import main


def test_handle_post_success(capsys):
    pm = SimpleNamespace(
        get_encrypted_data=lambda: b"data",
        nostr_client=SimpleNamespace(
            publish_json_to_nostr=lambda data, alt_summary=None: True
        ),
    )
    main.handle_post_to_nostr(pm)
    out = capsys.readouterr().out
    assert "✅ Sync complete." in out


def test_handle_post_failure(capsys):
    pm = SimpleNamespace(
        get_encrypted_data=lambda: b"data",
        nostr_client=SimpleNamespace(
            publish_json_to_nostr=lambda data, alt_summary=None: False
        ),
    )
    main.handle_post_to_nostr(pm)
    out = capsys.readouterr().out
    assert "❌ Sync failed…" in out
