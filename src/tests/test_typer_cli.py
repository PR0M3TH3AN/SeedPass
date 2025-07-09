import sys
from types import SimpleNamespace
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from typer.testing import CliRunner

from seedpass.cli import app, PasswordManager
from seedpass import cli
from password_manager.entry_types import EntryType

runner = CliRunner()


def test_entry_list(monkeypatch):
    called = {}

    def list_entries(sort_by="index", filter_kind=None, include_archived=False):
        called["args"] = (sort_by, filter_kind, include_archived)
        return [(0, "Site", "user", "", False)]

    pm = SimpleNamespace(
        entry_manager=SimpleNamespace(list_entries=list_entries),
        select_fingerprint=lambda fp: None,
    )
    monkeypatch.setattr(cli, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["entry", "list"])
    assert result.exit_code == 0
    assert "Site" in result.stdout
    assert called["args"] == ("index", None, False)


def test_entry_search(monkeypatch):
    pm = SimpleNamespace(
        entry_manager=SimpleNamespace(
            search_entries=lambda q: [(1, "L", None, None, False)]
        ),
        select_fingerprint=lambda fp: None,
    )
    monkeypatch.setattr(cli, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["entry", "search", "l"])
    assert result.exit_code == 0
    assert "1: L" in result.stdout


def test_entry_get_password(monkeypatch):
    def search(q):
        return [(2, "Example", "", "", False)]

    entry = {"type": EntryType.PASSWORD.value, "length": 8}
    pm = SimpleNamespace(
        entry_manager=SimpleNamespace(
            search_entries=search,
            retrieve_entry=lambda i: entry,
            get_totp_code=lambda i, s: "",
        ),
        password_generator=SimpleNamespace(generate_password=lambda l, i: "pw"),
        parent_seed="seed",
        select_fingerprint=lambda fp: None,
    )
    monkeypatch.setattr(cli, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["entry", "get", "ex"])
    assert result.exit_code == 0
    assert "pw" in result.stdout


def test_vault_export(monkeypatch, tmp_path):
    called = {}

    def export_db(path):
        called["path"] = path

    pm = SimpleNamespace(
        handle_export_database=export_db, select_fingerprint=lambda fp: None
    )
    monkeypatch.setattr(cli, "PasswordManager", lambda: pm)
    out_path = tmp_path / "out.json"
    result = runner.invoke(app, ["vault", "export", "--file", str(out_path)])
    assert result.exit_code == 0
    assert called["path"] == out_path


def test_nostr_get_pubkey(monkeypatch):
    pm = SimpleNamespace(
        nostr_client=SimpleNamespace(
            key_manager=SimpleNamespace(get_npub=lambda: "np")
        ),
        select_fingerprint=lambda fp: None,
    )
    monkeypatch.setattr(cli, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["nostr", "get-pubkey"])
    assert result.exit_code == 0
    assert "np" in result.stdout


def test_fingerprint_list(monkeypatch):
    pm = SimpleNamespace(
        fingerprint_manager=SimpleNamespace(list_fingerprints=lambda: ["a", "b"]),
        select_fingerprint=lambda fp: None,
    )
    monkeypatch.setattr(cli, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["fingerprint", "list"])
    assert result.exit_code == 0
    assert "a" in result.stdout and "b" in result.stdout


def test_config_get(monkeypatch):
    pm = SimpleNamespace(
        config_manager=SimpleNamespace(
            load_config=lambda require_pin=False: {"x": "1"}
        ),
        select_fingerprint=lambda fp: None,
    )
    monkeypatch.setattr(cli, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["config", "get", "x"])
    assert result.exit_code == 0
    assert "1" in result.stdout


def test_nostr_sync(monkeypatch):
    called = {}

    def sync_vault():
        called["called"] = True
        return "evt123"

    pm = SimpleNamespace(sync_vault=sync_vault, select_fingerprint=lambda fp: None)
    monkeypatch.setattr(cli, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["nostr", "sync"])
    assert result.exit_code == 0
    assert called.get("called") is True
    assert "evt123" in result.stdout


def test_generate_password(monkeypatch):
    called = {}

    def gen_pw(length):
        called["length"] = length
        return "secretpw"

    pm = SimpleNamespace(
        password_generator=SimpleNamespace(generate_password=gen_pw),
        select_fingerprint=lambda fp: None,
    )
    monkeypatch.setattr(cli, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["util", "generate-password", "--length", "12"])
    assert result.exit_code == 0
    assert called.get("length") == 12
    assert "secretpw" in result.stdout
