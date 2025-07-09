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


def test_vault_import(monkeypatch, tmp_path):
    called = {}

    def import_db(path):
        called["path"] = path

    pm = SimpleNamespace(
        handle_import_database=import_db, select_fingerprint=lambda fp: None
    )
    monkeypatch.setattr(cli, "PasswordManager", lambda: pm)
    in_path = tmp_path / "in.json"
    in_path.write_text("{}")
    result = runner.invoke(app, ["vault", "import", "--file", str(in_path)])
    assert result.exit_code == 0
    assert called["path"] == in_path


def test_vault_change_password(monkeypatch):
    called = {}

    def change_pw():
        called["called"] = True

    pm = SimpleNamespace(change_password=change_pw, select_fingerprint=lambda fp: None)
    monkeypatch.setattr(cli, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["vault", "change-password"])
    assert result.exit_code == 0
    assert called.get("called") is True


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


def test_fingerprint_add(monkeypatch):
    called = {}

    def add():
        called["add"] = True

    pm = SimpleNamespace(
        add_new_fingerprint=add,
        select_fingerprint=lambda fp: None,
        fingerprint_manager=SimpleNamespace(),
    )
    monkeypatch.setattr(cli, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["fingerprint", "add"])
    assert result.exit_code == 0
    assert called.get("add") is True


def test_fingerprint_remove(monkeypatch):
    called = {}

    def remove(fp):
        called["fp"] = fp

    pm = SimpleNamespace(
        fingerprint_manager=SimpleNamespace(remove_fingerprint=remove),
        select_fingerprint=lambda fp: None,
    )
    monkeypatch.setattr(cli, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["fingerprint", "remove", "abc"])
    assert result.exit_code == 0
    assert called.get("fp") == "abc"


def test_fingerprint_switch(monkeypatch):
    called = {}

    def switch(fp):
        called["fp"] = fp

    pm = SimpleNamespace(
        select_fingerprint=switch, fingerprint_manager=SimpleNamespace()
    )
    monkeypatch.setattr(cli, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["fingerprint", "switch", "def"])
    assert result.exit_code == 0
    assert called.get("fp") == "def"


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


def test_config_set(monkeypatch):
    called = {}

    def set_timeout(val):
        called["timeout"] = float(val)

    pm = SimpleNamespace(
        config_manager=SimpleNamespace(set_inactivity_timeout=set_timeout),
        select_fingerprint=lambda fp: None,
    )
    monkeypatch.setattr(cli, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["config", "set", "inactivity_timeout", "5"])
    assert result.exit_code == 0
    assert called["timeout"] == 5.0
    assert "Updated" in result.stdout


def test_config_set_unknown_key(monkeypatch):
    pm = SimpleNamespace(
        config_manager=SimpleNamespace(), select_fingerprint=lambda fp: None
    )
    monkeypatch.setattr(cli, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["config", "set", "bogus", "val"])
    assert result.exit_code != 0
    assert "Unknown key" in result.stdout


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


def test_api_start_passes_fingerprint(monkeypatch):
    """Ensure the API start command forwards the selected fingerprint."""
    called = {}

    def fake_start(fp=None):
        called["fp"] = fp
        return "tok"

    monkeypatch.setattr(cli.api_module, "start_server", fake_start)
    monkeypatch.setattr(cli, "uvicorn", SimpleNamespace(run=lambda *a, **k: None))

    result = runner.invoke(app, ["--fingerprint", "abc", "api", "start"])
    assert result.exit_code == 0
    assert called.get("fp") == "abc"


def test_entry_add(monkeypatch):
    called = {}

    def add_entry(label, length, username=None, url=None):
        called["args"] = (label, length, username, url)
        return 2

    pm = SimpleNamespace(
        entry_manager=SimpleNamespace(add_entry=add_entry),
        select_fingerprint=lambda fp: None,
    )
    monkeypatch.setattr(cli, "PasswordManager", lambda: pm)
    result = runner.invoke(
        app,
        [
            "entry",
            "add",
            "Example",
            "--length",
            "16",
            "--username",
            "bob",
            "--url",
            "ex.com",
        ],
    )
    assert result.exit_code == 0
    assert "2" in result.stdout
    assert called["args"] == ("Example", 16, "bob", "ex.com")


def test_entry_modify(monkeypatch):
    called = {}

    def modify_entry(index, username=None, url=None, notes=None, label=None, **kwargs):
        called["args"] = (index, username, url, notes, label, kwargs)

    pm = SimpleNamespace(
        entry_manager=SimpleNamespace(modify_entry=modify_entry),
        select_fingerprint=lambda fp: None,
    )
    monkeypatch.setattr(cli, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["entry", "modify", "1", "--username", "alice"])
    assert result.exit_code == 0
    assert called["args"][:5] == (1, "alice", None, None, None)


def test_entry_archive(monkeypatch):
    called = {}

    def archive_entry(i):
        called["id"] = i

    pm = SimpleNamespace(
        entry_manager=SimpleNamespace(archive_entry=archive_entry),
        select_fingerprint=lambda fp: None,
    )
    monkeypatch.setattr(cli, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["entry", "archive", "3"])
    assert result.exit_code == 0
    assert "3" in result.stdout
    assert called["id"] == 3


def test_entry_unarchive(monkeypatch):
    called = {}

    def restore_entry(i):
        called["id"] = i

    pm = SimpleNamespace(
        entry_manager=SimpleNamespace(restore_entry=restore_entry),
        select_fingerprint=lambda fp: None,
    )
    monkeypatch.setattr(cli, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["entry", "unarchive", "4"])
    assert result.exit_code == 0
    assert "4" in result.stdout
    assert called["id"] == 4


def test_verify_checksum_command(monkeypatch):
    called = {}

    pm = SimpleNamespace(
        handle_verify_checksum=lambda: called.setdefault("called", True),
        handle_update_script_checksum=lambda: None,
        select_fingerprint=lambda fp: None,
    )
    monkeypatch.setattr(cli, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["util", "verify-checksum"])
    assert result.exit_code == 0
    assert called.get("called") is True


def test_update_checksum_command(monkeypatch):
    called = {}

    pm = SimpleNamespace(
        handle_verify_checksum=lambda: None,
        handle_update_script_checksum=lambda: called.setdefault("called", True),
        select_fingerprint=lambda fp: None,
    )
    monkeypatch.setattr(cli, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["util", "update-checksum"])
    assert result.exit_code == 0
    assert called.get("called") is True
