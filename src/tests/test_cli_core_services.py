from types import SimpleNamespace

import typer
from typer.testing import CliRunner

from seedpass import cli
from seedpass.cli import app

runner = CliRunner()


def test_cli_vault_unlock(monkeypatch):
    called = {}

    def unlock_vault(pw):
        called["pw"] = pw
        return 0.5

    pm = SimpleNamespace(unlock_vault=unlock_vault, select_fingerprint=lambda fp: None)
    monkeypatch.setattr(cli, "PasswordManager", lambda: pm)
    monkeypatch.setattr(cli.typer, "prompt", lambda *a, **k: "pw")
    result = runner.invoke(app, ["vault", "unlock"])
    assert result.exit_code == 0
    assert "Unlocked in" in result.stdout
    assert called["pw"] == "pw"


def test_cli_entry_add_search_sync(monkeypatch):
    calls = {}

    def add_entry(label, length, username=None, url=None):
        calls["add"] = (label, length, username, url)
        return 1

    def search_entries(q, kinds=None):
        calls["search"] = (q, kinds)
        return [(1, "Label", None, None, False)]

    def sync_vault():
        calls["sync"] = True
        return {"manifest_id": "m", "chunk_ids": [], "delta_ids": []}

    pm = SimpleNamespace(
        entry_manager=SimpleNamespace(
            add_entry=add_entry, search_entries=search_entries
        ),
        sync_vault=sync_vault,
        select_fingerprint=lambda fp: None,
    )
    monkeypatch.setattr(cli, "PasswordManager", lambda: pm)

    # entry add
    result = runner.invoke(app, ["entry", "add", "Label"])
    assert result.exit_code == 0
    assert "1" in result.stdout
    assert calls["add"] == ("Label", 12, None, None)
    assert calls.get("sync") is True

    # entry search
    result = runner.invoke(
        app, ["entry", "search", "lab", "--kind", "password", "--kind", "totp"]
    )
    assert result.exit_code == 0
    assert "Label" in result.stdout
    assert calls["search"] == ("lab", ["password", "totp"])

    # nostr sync
    result = runner.invoke(app, ["nostr", "sync"])
    assert result.exit_code == 0
    assert "manifest" in result.stdout.lower()
    assert calls.get("sync") is True
