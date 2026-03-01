from types import SimpleNamespace

import typer
from typer.testing import CliRunner

from seedpass import cli
from seedpass.cli import app
from seedpass.cli import common as cli_common
from seedpass.core.entry_types import EntryType

runner = CliRunner()


def test_cli_vault_unlock(monkeypatch):
    called = {}

    def unlock_vault(pw):
        called["pw"] = pw
        return 0.5

    pm = SimpleNamespace(unlock_vault=unlock_vault, select_fingerprint=lambda fp: None)
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: pm)
    monkeypatch.setattr(cli.typer, "prompt", lambda *a, **k: "pw")
    result = runner.invoke(app, ["vault", "unlock"])
    assert result.exit_code == 0
    assert "Unlocked in" in result.stdout
    assert "seedpass --help" in result.stdout
    assert called["pw"] == "pw"


def test_cli_vault_unlock_with_env_broker(monkeypatch):
    called = {}
    broker_called = {}

    def unlock_vault(pw):
        called["pw"] = pw
        return 0.25

    pm = SimpleNamespace(unlock_vault=unlock_vault, select_fingerprint=lambda fp: None)
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: pm)
    monkeypatch.setattr(
        "seedpass.cli.vault.resolve_broker_password",
        lambda **kwargs: broker_called.update(kwargs) or "broker-pw",
    )
    monkeypatch.setattr(
        cli.typer,
        "prompt",
        lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("prompt should not be called")
        ),
    )
    result = runner.invoke(app, ["vault", "unlock", "--auth-broker", "env"])
    assert result.exit_code == 0
    assert called["pw"] == "broker-pw"
    assert broker_called["broker"] == "env"


def test_cli_entry_add_search_sync(monkeypatch):
    calls = {}

    def add_entry(label, length, username=None, url=None):
        calls["add"] = (label, length, username, url)
        return 1

    def search_entries(q, kinds=None):
        calls["search"] = (q, kinds)
        return [(1, "Label", None, None, False, EntryType.PASSWORD)]

    def start_background_vault_sync():
        calls["sync"] = True
        return {"manifest_id": "m", "chunk_ids": [], "delta_ids": []}

    pm = SimpleNamespace(
        entry_manager=SimpleNamespace(
            add_entry=add_entry, search_entries=search_entries
        ),
        start_background_vault_sync=start_background_vault_sync,
        sync_vault=lambda: {"manifest_id": "m", "chunk_ids": [], "delta_ids": []},
        select_fingerprint=lambda fp: None,
    )
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: pm)

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
