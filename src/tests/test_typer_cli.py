import sys
from types import SimpleNamespace
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from typer.testing import CliRunner

from seedpass.cli import app
from seedpass.cli import common as cli_common
from seedpass.cli import api as cli_api
from seedpass import cli
from seedpass.core.entry_types import EntryType

runner = CliRunner()


def test_entry_list(monkeypatch):
    called = {}

    def list_entries(sort_by="index", filter_kinds=None, include_archived=False):
        called["args"] = (sort_by, filter_kinds, include_archived)
        return [(0, "Site", "user", "", False)]

    pm = SimpleNamespace(
        entry_manager=SimpleNamespace(list_entries=list_entries),
        select_fingerprint=lambda fp: None,
    )
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["entry", "list"])
    assert result.exit_code == 0
    assert "Site" in result.stdout
    assert called["args"] == ("index", None, False)


def test_entry_search(monkeypatch):
    pm = SimpleNamespace(
        entry_manager=SimpleNamespace(
            search_entries=lambda q, kinds=None: [
                (1, "L", None, None, False, EntryType.PASSWORD)
            ]
        ),
        select_fingerprint=lambda fp: None,
    )
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["entry", "search", "l"])
    assert result.exit_code == 0
    assert "Password - L" in result.stdout


def test_entry_get_password(monkeypatch):
    def search(q, kinds=None):
        return [(2, "Example", "", "", False, EntryType.PASSWORD)]

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
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["entry", "get", "ex"])
    assert result.exit_code == 0
    assert "pw" in result.stdout


def test_vault_export(monkeypatch, tmp_path):
    called = {}

    def export_profile(self):
        called["export"] = True
        return b"data"

    monkeypatch.setattr(cli_common.VaultService, "export_profile", export_profile)
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: SimpleNamespace())
    out_path = tmp_path / "out.json"
    result = runner.invoke(app, ["vault", "export", "--file", str(out_path)])
    assert result.exit_code == 0
    assert called.get("export") is True
    assert out_path.read_bytes() == b"data"


def test_vault_import(monkeypatch, tmp_path):
    called = {}

    def import_profile(self, data):
        called["data"] = data

    monkeypatch.setattr(cli_common.VaultService, "import_profile", import_profile)
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: SimpleNamespace())
    in_path = tmp_path / "in.json"
    in_path.write_bytes(b"inp")
    result = runner.invoke(app, ["vault", "import", "--file", str(in_path)])
    assert result.exit_code == 0
    assert called["data"] == b"inp"


def test_vault_import_triggers_sync(monkeypatch, tmp_path):
    called = {}

    def import_profile(self, data):
        called["data"] = data
        self._manager.sync_vault()

    def sync_vault():
        called["sync"] = True

    monkeypatch.setattr(cli_common.VaultService, "import_profile", import_profile)
    monkeypatch.setattr(
        cli_common, "PasswordManager", lambda: SimpleNamespace(sync_vault=sync_vault)
    )
    in_path = tmp_path / "in.json"
    in_path.write_bytes(b"inp")
    result = runner.invoke(app, ["vault", "import", "--file", str(in_path)])
    assert result.exit_code == 0
    assert called.get("data") == b"inp"
    assert called.get("sync") is True


def test_vault_change_password(monkeypatch):
    called = {}

    def change_pw(old, new):
        called["args"] = (old, new)

    pm = SimpleNamespace(change_password=change_pw, select_fingerprint=lambda fp: None)
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["vault", "change-password"], input="old\nnew\nnew\n")
    assert result.exit_code == 0
    assert called.get("args") == ("old", "new")


def test_vault_lock(monkeypatch):
    called = {}

    def lock():
        called["locked"] = True
        pm.locked = True

    pm = SimpleNamespace(
        lock_vault=lock,
        locked=False,
        select_fingerprint=lambda fp: None,
        fingerprint_dir="/does/not/matter",
        start_background_sync=lambda: None,
    )
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["vault", "lock"])
    assert result.exit_code == 0
    assert called.get("locked") is True
    assert pm.locked is True


def test_root_lock(monkeypatch):
    called = {}

    def lock():
        called["locked"] = True
        pm.locked = True

    pm = SimpleNamespace(
        lock_vault=lock,
        locked=False,
        select_fingerprint=lambda fp: None,
        fingerprint_dir="/does/not/matter",
        start_background_sync=lambda: None,
    )
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["lock"])
    assert result.exit_code == 0
    assert called.get("locked") is True
    assert pm.locked is True


def test_vault_reveal_parent_seed(monkeypatch, tmp_path):
    called = {}

    def reveal(path=None, **_):
        called["path"] = path

    pm = SimpleNamespace(
        handle_backup_reveal_parent_seed=reveal, select_fingerprint=lambda fp: None
    )
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: pm)
    out_path = tmp_path / "seed.enc"
    result = runner.invoke(
        app,
        ["vault", "reveal-parent-seed", "--file", str(out_path)],
        input="pw\n",
    )
    assert result.exit_code == 0
    assert called["path"] == out_path


def test_nostr_get_pubkey(monkeypatch):
    pm = SimpleNamespace(
        nostr_client=SimpleNamespace(
            key_manager=SimpleNamespace(get_npub=lambda: "np")
        ),
        select_fingerprint=lambda fp: None,
    )
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["nostr", "get-pubkey"])
    assert result.exit_code == 0
    assert "np" in result.stdout


def test_fingerprint_list(monkeypatch):
    pm = SimpleNamespace(
        fingerprint_manager=SimpleNamespace(list_fingerprints=lambda: ["a", "b"]),
        select_fingerprint=lambda fp: None,
    )
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: pm)
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
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: pm)
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
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["fingerprint", "remove", "abc"])
    assert result.exit_code == 0
    assert called.get("fp") == "abc"


def test_fingerprint_switch(monkeypatch):
    called = {}

    def switch(fp, **_):
        called["fp"] = fp

    pm = SimpleNamespace(
        select_fingerprint=switch, fingerprint_manager=SimpleNamespace()
    )
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["fingerprint", "switch", "def"], input="pw\n")
    assert result.exit_code == 0
    assert called.get("fp") == "def"


def test_config_get(monkeypatch):
    pm = SimpleNamespace(
        config_manager=SimpleNamespace(
            load_config=lambda require_pin=False: {"x": "1"}
        ),
        select_fingerprint=lambda fp: None,
    )
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: pm)
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
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["config", "set", "inactivity_timeout", "5"])
    assert result.exit_code == 0
    assert called["timeout"] == 5.0
    assert "Updated" in result.stdout


def test_config_set_unknown_key(monkeypatch):
    pm = SimpleNamespace(
        config_manager=SimpleNamespace(), select_fingerprint=lambda fp: None
    )
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["config", "set", "bogus", "val"])
    assert result.exit_code != 0
    assert "Unknown key" in result.stdout


def test_nostr_sync(monkeypatch):
    called = {}

    def sync_vault():
        called["called"] = True
        return {
            "manifest_id": "evt123",
            "chunk_ids": ["c1"],
            "delta_ids": ["d1"],
        }

    pm = SimpleNamespace(sync_vault=sync_vault, select_fingerprint=lambda fp: None)
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["nostr", "sync"])
    assert result.exit_code == 0
    assert called.get("called") is True
    assert "evt123" in result.stdout
    assert "c1" in result.stdout
    assert "d1" in result.stdout


def test_generate_password(monkeypatch):
    called = {}

    def gen_pw(length, **kwargs):
        called["length"] = length
        called["kwargs"] = kwargs
        return "secretpw"

    monkeypatch.setattr(
        cli_common,
        "PasswordManager",
        lambda: SimpleNamespace(select_fingerprint=lambda fp: None),
    )
    monkeypatch.setattr(
        cli_common,
        "UtilityService",
        lambda pm: SimpleNamespace(generate_password=gen_pw),
    )
    result = runner.invoke(
        app,
        [
            "util",
            "generate-password",
            "--length",
            "12",
            "--no-special",
            "--allowed-special-chars",
            "!@",
            "--special-mode",
            "safe",
            "--exclude-ambiguous",
            "--min-uppercase",
            "1",
            "--min-lowercase",
            "2",
            "--min-digits",
            "3",
            "--min-special",
            "4",
        ],
    )
    assert result.exit_code == 0
    assert called.get("length") == 12
    assert called.get("kwargs") == {
        "include_special_chars": False,
        "allowed_special_chars": "!@",
        "special_mode": "safe",
        "exclude_ambiguous": True,
        "min_uppercase": 1,
        "min_lowercase": 2,
        "min_digits": 3,
        "min_special": 4,
    }
    assert "secretpw" in result.stdout


def test_api_start_passes_fingerprint(monkeypatch):
    """Ensure the API start command forwards the selected fingerprint."""
    called = {}

    def fake_start(fp=None):
        called["fp"] = fp
        return "tok"

    monkeypatch.setattr(cli_api.api_module, "start_server", fake_start)
    monkeypatch.setattr(cli_api, "uvicorn", SimpleNamespace(run=lambda *a, **k: None))

    result = runner.invoke(app, ["--fingerprint", "abc", "api", "start"])
    assert result.exit_code == 0
    assert called.get("fp") == "abc"


def test_entry_list_passes_fingerprint(monkeypatch):
    """Ensure entry commands receive the fingerprint."""
    called = {}

    class PM:
        def __init__(self, fingerprint=None):
            called["fp"] = fingerprint
            self.entry_manager = SimpleNamespace(list_entries=lambda *a, **k: [])

    monkeypatch.setattr(cli_common, "PasswordManager", PM)
    result = runner.invoke(app, ["--fingerprint", "abc", "entry", "list"])
    assert result.exit_code == 0
    assert called.get("fp") == "abc"


def test_entry_add(monkeypatch):
    called = {}

    def add_entry(label, length, username=None, url=None, **kwargs):
        called["args"] = (label, length, username, url)
        called["kwargs"] = kwargs
        return 2

    pm = SimpleNamespace(
        entry_manager=SimpleNamespace(add_entry=add_entry),
        select_fingerprint=lambda fp: None,
        start_background_vault_sync=lambda: None,
    )
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: pm)
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
            "--no-special",
            "--allowed-special-chars",
            "!@",
            "--special-mode",
            "safe",
            "--exclude-ambiguous",
            "--min-uppercase",
            "1",
            "--min-lowercase",
            "2",
            "--min-digits",
            "3",
            "--min-special",
            "4",
        ],
    )
    assert result.exit_code == 0
    assert "2" in result.stdout
    assert called["args"] == ("Example", 16, "bob", "ex.com")
    assert called["kwargs"] == {
        "include_special_chars": False,
        "allowed_special_chars": "!@",
        "special_mode": "safe",
        "exclude_ambiguous": True,
        "min_uppercase": 1,
        "min_lowercase": 2,
        "min_digits": 3,
        "min_special": 4,
    }


def test_entry_modify(monkeypatch):
    called = {}

    def modify_entry(
        index, username=None, url=None, notes=None, label=None, key=None, **kwargs
    ):
        called["args"] = (index, username, url, notes, label, key, kwargs)

    pm = SimpleNamespace(
        entry_manager=SimpleNamespace(modify_entry=modify_entry),
        select_fingerprint=lambda fp: None,
        start_background_vault_sync=lambda: None,
    )
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["entry", "modify", "1", "--username", "alice"])
    assert result.exit_code == 0
    assert called["args"][:6] == (1, "alice", None, None, None, None)


def test_entry_modify_invalid(monkeypatch):
    def modify_entry(*a, **k):
        raise ValueError("bad")

    pm = SimpleNamespace(
        entry_manager=SimpleNamespace(modify_entry=modify_entry),
        select_fingerprint=lambda fp: None,
        start_background_vault_sync=lambda: None,
    )
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["entry", "modify", "1", "--username", "alice"])
    assert result.exit_code == 1
    assert "bad" in result.stdout


def test_entry_archive(monkeypatch):
    called = {}

    def archive_entry(i):
        called["id"] = i

    pm = SimpleNamespace(
        entry_manager=SimpleNamespace(archive_entry=archive_entry),
        select_fingerprint=lambda fp: None,
        start_background_vault_sync=lambda: None,
    )
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: pm)
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
        start_background_vault_sync=lambda: None,
    )
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["entry", "unarchive", "4"])
    assert result.exit_code == 0
    assert "4" in result.stdout
    assert called["id"] == 4


def test_entry_export_totp(monkeypatch, tmp_path):
    called = {}

    pm = SimpleNamespace(
        entry_manager=SimpleNamespace(
            export_totp_entries=lambda seed: called.setdefault("called", True)
            or {"entries": []}
        ),
        parent_seed="seed",
        select_fingerprint=lambda fp: None,
    )
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: pm)

    out = tmp_path / "t.json"
    result = runner.invoke(app, ["entry", "export-totp", "--file", str(out)])
    assert result.exit_code == 0
    assert out.exists()
    assert called.get("called") is True


def test_entry_totp_codes(monkeypatch):
    called = {}

    pm = SimpleNamespace(
        handle_display_totp_codes=lambda: called.setdefault("called", True),
        select_fingerprint=lambda fp: None,
    )
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["entry", "totp-codes"])
    assert result.exit_code == 0
    assert called.get("called") is True


def test_verify_checksum_command(monkeypatch):
    called = {}

    pm = SimpleNamespace(
        handle_verify_checksum=lambda: called.setdefault("called", True),
        handle_update_script_checksum=lambda: None,
        select_fingerprint=lambda fp: None,
    )
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: pm)
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
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: pm)
    result = runner.invoke(app, ["util", "update-checksum"])
    assert result.exit_code == 0
    assert called.get("called") is True


def test_tui_forward_fingerprint(monkeypatch):
    """Ensure --fingerprint is forwarded when launching the TUI."""
    called = {}

    def fake_main(*, fingerprint=None):
        called["fp"] = fingerprint
        return 0

    fake_mod = SimpleNamespace(main=fake_main)
    monkeypatch.setattr(
        cli, "importlib", SimpleNamespace(import_module=lambda n: fake_mod)
    )

    result = runner.invoke(app, ["--fingerprint", "abc"])
    assert result.exit_code == 0
    assert called.get("fp") == "abc"


def test_gui_command(monkeypatch):
    called = {}

    def fake_main():
        called["called"] = True

    monkeypatch.setitem(
        sys.modules,
        "seedpass_gui.app",
        SimpleNamespace(main=fake_main),
    )
    monkeypatch.setattr(cli.importlib.util, "find_spec", lambda n: True)
    result = runner.invoke(app, ["gui"])
    assert result.exit_code == 0
    assert called.get("called") is True


def test_gui_command_no_backend(monkeypatch):
    """Exit with message when backend is missing."""

    monkeypatch.setattr(cli, "_gui_backend_available", lambda: False)

    result = runner.invoke(app, ["gui"])
    assert result.exit_code == 1
    assert "Please install" in result.output


def test_gui_command_install_backend(monkeypatch):
    """Install backend on request and launch GUI."""

    call_count = {"n": 0}

    def backend_available() -> bool:
        call_count["n"] += 1
        return call_count["n"] > 1

    monkeypatch.setattr(cli, "_gui_backend_available", backend_available)

    installed = {}

    def fake_check_call(cmd):
        installed["cmd"] = cmd

    monkeypatch.setattr(cli.subprocess, "check_call", fake_check_call)

    called = {}

    def fake_main():
        called["gui"] = True

    monkeypatch.setitem(
        sys.modules,
        "seedpass_gui.app",
        SimpleNamespace(main=fake_main),
    )

    result = runner.invoke(app, ["gui", "--install"], input="y\n")
    assert result.exit_code == 0
    assert installed.get("cmd") is not None
    assert called.get("gui") is True
