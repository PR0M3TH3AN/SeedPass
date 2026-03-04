import sys
import json
from types import SimpleNamespace
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from typer.testing import CliRunner

from seedpass.cli import app
from seedpass.cli import common as cli_common
from seedpass.cli import api as cli_api
from seedpass import cli
from seedpass.core.entry_types import EntryType
import seedpass.core.agent_export_policy as export_policy
import seedpass.core.agent_approval as approval_core
import seedpass.core.agent_secret_isolation as isolation_core

runner = CliRunner()


def test_legacy_command_invokes_legacy_tui(monkeypatch):
    called = {}

    def fake_launch_legacy_tui(*, fingerprint=None):
        called["fingerprint"] = fingerprint
        raise typer.Exit(0)

    import typer

    monkeypatch.setattr(cli, "_launch_legacy_tui", fake_launch_legacy_tui)
    result = runner.invoke(app, ["legacy"])
    assert result.exit_code == 0
    assert called["fingerprint"] is None


def test_legacy_flag_invokes_legacy_tui(monkeypatch):
    called = {}

    def fake_launch_legacy_tui(*, fingerprint=None):
        called["fingerprint"] = fingerprint
        raise typer.Exit(0)

    import typer

    monkeypatch.setattr(cli, "_launch_legacy_tui", fake_launch_legacy_tui)
    result = runner.invoke(app, ["--legacy-tui"])
    assert result.exit_code == 0
    assert called["fingerprint"] is None


def test_entry_list(monkeypatch):
    called = {}

    def list_entries(sort_by="index", filter_kinds=None, include_archived=False):
        called["args"] = (sort_by, filter_kinds, include_archived)
        return [(0, "Site", "user", "", False)]

    pm = SimpleNamespace(
        entry_manager=SimpleNamespace(list_entries=list_entries),
        select_fingerprint=lambda fp: None,
    )
    monkeypatch.setattr(cli_common, "PasswordManager", lambda *a, **k: pm)
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


def test_vault_export_denied_for_agent_profile_by_default(monkeypatch, tmp_path):
    events = {}
    monkeypatch.setattr(export_policy, "APP_DIR", tmp_path)
    monkeypatch.setattr(cli_common.VaultService, "export_profile", lambda self: b"data")
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: SimpleNamespace())
    monkeypatch.setattr(
        "seedpass.cli.vault.record_export_policy_event",
        lambda event, details: events.setdefault("event", (event, details)),
    )
    out_path = tmp_path / "out.json"
    result = runner.invoke(
        app, ["vault", "export", "--file", str(out_path), "--agent-profile"]
    )
    assert result.exit_code == 1
    assert "policy_deny:full_export_blocked" in result.stdout
    assert events["event"][0] == "export_denied"


def test_vault_export_policy_filtered_includes_manifest(monkeypatch, tmp_path):
    monkeypatch.setattr(export_policy, "APP_DIR", tmp_path)
    (tmp_path / "agent_policy.json").write_text(
        json.dumps(
            {
                "allow_kinds": ["password"],
                "allow_export_import": False,
                "output": {"safe_output_default": True, "redact_fields": ["value"]},
            }
        ),
        encoding="utf-8",
    )

    class Enc:
        def encrypt_data(self, payload):
            return payload

    index_data = {
        "schema_version": 4,
        "entries": {
            "0": {"kind": "password", "label": "ok"},
            "1": {"kind": "totp", "label": "skip"},
        },
    }
    pm = SimpleNamespace(
        vault=SimpleNamespace(load_index=lambda: index_data, encryption_manager=Enc()),
        select_fingerprint=lambda fp: None,
    )
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: pm)
    out_path = tmp_path / "filtered.enc"
    result = runner.invoke(
        app,
        [
            "vault",
            "export",
            "--file",
            str(out_path),
            "--agent-profile",
            "--policy-filtered",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    manifest = payload["_export_manifest"]
    assert manifest["mode"] == "policy_filtered"
    assert manifest["allow_kinds"] == ["password"]
    assert manifest["included_entry_indexes"] == ["0"]


def test_vault_export_agent_requires_approval_for_full_export(monkeypatch, tmp_path):
    monkeypatch.setattr(export_policy, "APP_DIR", tmp_path)
    monkeypatch.setattr(approval_core, "APP_DIR", tmp_path)
    (tmp_path / "agent_policy.json").write_text(
        json.dumps(
            {
                "allow_kinds": ["password"],
                "allow_export_import": True,
                "export": {"allow_full_vault": True},
                "approvals": {"require_for": ["export"]},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(cli_common.VaultService, "export_profile", lambda self: b"data")
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: SimpleNamespace())

    out_path = tmp_path / "needs-approval.enc"
    result = runner.invoke(
        app,
        [
            "vault",
            "export",
            "--file",
            str(out_path),
            "--agent-profile",
        ],
    )
    assert result.exit_code == 1
    assert "policy_deny:approval_required" in result.stdout


def test_vault_export_agent_full_succeeds_with_approval(monkeypatch, tmp_path):
    monkeypatch.setattr(export_policy, "APP_DIR", tmp_path)
    monkeypatch.setattr(approval_core, "APP_DIR", tmp_path)
    (tmp_path / "agent_policy.json").write_text(
        json.dumps(
            {
                "allow_kinds": ["password"],
                "allow_export_import": True,
                "export": {"allow_full_vault": True},
                "approvals": {"require_for": ["export"]},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(cli_common.VaultService, "export_profile", lambda self: b"data")
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: SimpleNamespace())
    approval = approval_core.issue_approval(
        action="export",
        ttl_seconds=300,
        uses=1,
        resource="vault:full",
    )

    out_path = tmp_path / "approved.enc"
    result = runner.invoke(
        app,
        [
            "vault",
            "export",
            "--file",
            str(out_path),
            "--agent-profile",
            "--approval-id",
            approval["id"],
        ],
    )
    assert result.exit_code == 0
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
    monkeypatch.setattr(cli_common, "PasswordManager", lambda *a, **k: pm)
    out_path = tmp_path / "seed.enc"
    result = runner.invoke(
        app,
        ["vault", "reveal-parent-seed", "--file", str(out_path)],
        input="pw\n",
    )
    assert result.exit_code == 0
    assert called["path"] == out_path


def test_vault_reveal_parent_seed_agent_requires_approval(monkeypatch, tmp_path):
    called = {}
    monkeypatch.setattr(export_policy, "APP_DIR", tmp_path)
    monkeypatch.setattr(approval_core, "APP_DIR", tmp_path)
    (tmp_path / "agent_policy.json").write_text(
        json.dumps({"approvals": {"require_for": ["reveal_parent_seed"]}}),
        encoding="utf-8",
    )

    def reveal(path=None, **_):
        called["path"] = path

    pm = SimpleNamespace(
        handle_backup_reveal_parent_seed=reveal, select_fingerprint=lambda fp: None
    )
    monkeypatch.setattr(cli_common, "PasswordManager", lambda *a, **k: pm)
    out_path = tmp_path / "seed.enc"
    result = runner.invoke(
        app,
        [
            "vault",
            "reveal-parent-seed",
            "--file",
            str(out_path),
            "--agent-profile",
        ],
        input="pw\n",
    )
    assert result.exit_code == 1
    assert "policy_deny:approval_required" in result.stdout
    assert "path" not in called


def test_vault_reveal_parent_seed_blocked_when_high_risk_locked(monkeypatch, tmp_path):
    called = {}
    monkeypatch.setattr(export_policy, "APP_DIR", tmp_path)
    monkeypatch.setattr(isolation_core, "APP_DIR", tmp_path)
    (tmp_path / "agent_policy.json").write_text(
        json.dumps(
            {"secret_isolation": {"enabled": True, "high_risk_kinds": ["seed"]}}
        ),
        encoding="utf-8",
    )
    isolation_core.set_high_risk_factor("factor-1")

    def reveal(path=None, **_):
        called["path"] = path

    pm = SimpleNamespace(
        handle_backup_reveal_parent_seed=reveal, select_fingerprint=lambda fp: None
    )
    monkeypatch.setattr(cli_common, "PasswordManager", lambda *a, **k: pm)
    out_path = tmp_path / "seed.enc"
    result = runner.invoke(
        app,
        [
            "--fingerprint",
            "ABC123",
            "vault",
            "reveal-parent-seed",
            "--file",
            str(out_path),
        ],
        input="pw\n",
    )
    assert result.exit_code == 1
    assert "policy_deny:high_risk_locked" in result.stdout
    assert "path" not in called


def test_vault_reveal_parent_seed_agent_approval_allows(monkeypatch, tmp_path):
    called = {}
    monkeypatch.setattr(export_policy, "APP_DIR", tmp_path)
    monkeypatch.setattr(approval_core, "APP_DIR", tmp_path)
    (tmp_path / "agent_policy.json").write_text(
        json.dumps({"approvals": {"require_for": ["reveal_parent_seed"]}}),
        encoding="utf-8",
    )

    def reveal(path=None, **_):
        called["path"] = path

    pm = SimpleNamespace(
        handle_backup_reveal_parent_seed=reveal, select_fingerprint=lambda fp: None
    )
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: pm)
    approval = approval_core.issue_approval(
        action="reveal_parent_seed",
        ttl_seconds=300,
        uses=1,
        resource="vault:parent-seed",
    )
    out_path = tmp_path / "seed.enc"
    result = runner.invoke(
        app,
        [
            "vault",
            "reveal-parent-seed",
            "--file",
            str(out_path),
            "--agent-profile",
            "--approval-id",
            approval["id"],
        ],
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


def test_capabilities_text():
    result = runner.invoke(app, ["capabilities"])
    assert result.exit_code == 0
    assert "SeedPass Capabilities" in result.stdout
    assert "Auth brokers" in result.stdout
    assert "Sync safety" in result.stdout
    assert "Security posture checks" in result.stdout


def test_capabilities_json():
    result = runner.invoke(app, ["capabilities", "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == 1
    assert "cli" in payload["interfaces"]
    assert "agent" in payload["interfaces"]["cli"]["root_commands"]
    assert "tui3" in payload["interfaces"]["cli"]["root_commands"]
    assert "legacy" in payload["interfaces"]["cli"]["root_commands"]
    assert (
        "/api/v1/agent/job-profiles/{job_id}/template/verify"
        in payload["interfaces"]["api"]["discovery"]
    )
    assert "/api/v1/agent/recovery/split" in payload["interfaces"]["api"]["discovery"]
    assert (
        "/api/v1/agent/recovery/drills/verify"
        in payload["interfaces"]["api"]["discovery"]
    )
    assert "leases" in payload["security_features"]
    assert "automation" in payload["security_features"]
    assert "sync" in payload["security_features"]
    assert "policy" in payload["security_features"]
    assert payload["security_features"]["policy"]["supports_change_review"]
    assert (
        payload["security_features"]["sync"]["deterministic_conflict_resolution"]
        == "modified_ts_hash_tombstone_v2"
    )
    assert "export_controls" in payload["security_features"]
    assert payload["security_features"]["export_controls"][
        "supports_manifest_entry_hash_verification"
    ]
    assert "posture" in payload["security_features"]
    assert (
        "agent posture-remediate" in payload["security_features"]["posture"]["commands"]
    )
    assert payload["security_features"]["automation"][
        "supports_persistent_job_profiles"
    ]
    assert payload["security_features"]["automation"]["supports_api_templates"]
    assert (
        payload["security_features"]["automation"]["template_manifest_signing"]
        == "hmac-sha256"
    )
    assert payload["security_features"]["automation"]["enforces_policy_stamp_on_run"]
    assert payload["security_features"]["automation"]["supports_host_binding"]
    assert payload["security_features"]["recovery"]["supports_shamir_split_recover"]
    assert payload["security_features"]["recovery"]["supports_signed_drill_reports"]
    assert "identities" in payload["security_features"]
    assert "secret_isolation" in payload["security_features"]
    assert any("After unlock/login" in h for h in payload["help_hints"])


def test_api_start_passes_fingerprint(monkeypatch):
    """Ensure the API start command forwards the selected fingerprint."""
    called = {}

    def fake_start(fingerprint=None, token=None):
        called["fp"] = fingerprint
        return "tok"

    monkeypatch.setattr(cli_api.api_module, "start_server", fake_start)
    monkeypatch.setattr(cli_api, "uvicorn", SimpleNamespace(run=lambda *a, **k: None))

    result = runner.invoke(app, ["--fingerprint", "abc", "api", "start"])
    assert result.exit_code == 0
    assert called.get("fp") == "abc"


def test_version_flag(monkeypatch):
    monkeypatch.setattr(cli, "_get_cli_version", lambda: "9.9.9-test")
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "SeedPass 9.9.9-test" in result.stdout


def test_api_start_unlock_uses_env_broker(monkeypatch):
    called = {}
    broker_called = {}

    def fake_start(fingerprint=None, unlock_password=None):
        called["fp"] = fingerprint
        called["pw"] = unlock_password
        return "tok"

    monkeypatch.setattr(cli_api.api_module, "start_server", fake_start)
    monkeypatch.setattr(cli_api, "uvicorn", SimpleNamespace(run=lambda *a, **k: None))
    monkeypatch.setattr(
        cli_api,
        "resolve_broker_password",
        lambda **kwargs: broker_called.update(kwargs) or "broker-pw",
    )

    result = runner.invoke(
        app,
        [
            "--fingerprint",
            "abc",
            "api",
            "start",
            "--unlock",
            "--auth-broker",
            "env",
        ],
    )
    assert result.exit_code == 0
    assert called.get("fp") == "abc"
    assert called.get("pw") == "broker-pw"
    assert broker_called.get("broker") == "env"


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


def test_entry_export_totp_denied_for_agent_profile(monkeypatch, tmp_path):
    monkeypatch.setattr(export_policy, "APP_DIR", tmp_path)
    (tmp_path / "agent_policy.json").write_text(
        '{"allow_kinds":["password"],"allow_export_import":false}',
        encoding="utf-8",
    )
    pm = SimpleNamespace(
        entry_manager=SimpleNamespace(export_totp_entries=lambda seed: {"entries": []}),
        parent_seed="seed",
        select_fingerprint=lambda fp: None,
    )
    monkeypatch.setattr(cli_common, "PasswordManager", lambda: pm)
    out = tmp_path / "t.json"
    result = runner.invoke(
        app, ["entry", "export-totp", "--file", str(out), "--agent-profile"]
    )
    assert result.exit_code == 1
    assert "policy_deny:kind_not_allowed" in result.stdout


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


def test_root_tui2_forward_fingerprint(monkeypatch):
    """Ensure --fingerprint is forwarded when launching default TUI v2."""
    called = {}

    def fake_launch(**kwargs):
        called["fp"] = kwargs.get("fingerprint")
        called["factory"] = kwargs.get("entry_service_factory")
        return True

    monkeypatch.setattr(cli, "_get_entry_service", lambda _ctx: object())
    monkeypatch.setattr(cli, "launch_tui2", fake_launch)
    result = runner.invoke(app, ["--fingerprint", "abc"])
    assert result.exit_code == 0
    assert called.get("fp") == "abc"
    assert callable(called.get("factory"))


def test_root_legacy_tui_flag_forwards_fingerprint(monkeypatch):
    called = {}

    def fake_main(*, fingerprint=None):
        called["fp"] = fingerprint
        return 0

    fake_mod = SimpleNamespace(main=fake_main)
    monkeypatch.setattr(
        cli, "importlib", SimpleNamespace(import_module=lambda n: fake_mod)
    )

    result = runner.invoke(app, ["--legacy-tui", "--fingerprint", "abc"])
    assert result.exit_code == 0
    assert called.get("fp") == "abc"


def test_legacy_command_forwards_fingerprint(monkeypatch):
    called = {}

    def fake_main(*, fingerprint=None):
        called["fp"] = fingerprint
        return 0

    monkeypatch.setattr(
        cli,
        "importlib",
        SimpleNamespace(import_module=lambda _: SimpleNamespace(main=fake_main)),
    )
    result = runner.invoke(app, ["--fingerprint", "abc", "legacy"])
    assert result.exit_code == 0
    assert called.get("fp") == "abc"


def test_legacy_command_default_profile(monkeypatch):
    called = {}

    def fake_main(*, fingerprint=None):
        called["fp"] = fingerprint
        return 0

    monkeypatch.setattr(
        cli,
        "importlib",
        SimpleNamespace(import_module=lambda _: SimpleNamespace(main=fake_main)),
    )
    result = runner.invoke(app, ["legacy"])
    assert result.exit_code == 0
    assert called.get("fp") is None


def test_tui2_check(monkeypatch):
    monkeypatch.setattr(
        cli,
        "check_tui2_runtime",
        lambda: {"status": "ok", "backend": "textual", "textual_available": True},
    )
    result = runner.invoke(app, ["tui2", "--check"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["backend"] == "textual"
    assert payload["textual_available"] is True


def test_tui3_check(monkeypatch):
    monkeypatch.setattr(
        cli,
        "check_tui2_runtime",
        lambda: {"status": "ok", "backend": "textual", "textual_available": True},
    )
    result = runner.invoke(app, ["tui3", "--check"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert "textual_available" in payload


def test_tui2_unavailable_without_fallback(monkeypatch):
    monkeypatch.setattr(cli, "_get_entry_service", lambda _ctx: object())
    monkeypatch.setattr(cli, "launch_tui2", lambda **_: False)
    result = runner.invoke(app, ["tui2", "--no-fallback-legacy"])
    assert result.exit_code == 1
    assert "Install `textual`" in result.stderr


def test_tui2_fallback_legacy(monkeypatch):
    called = {}
    monkeypatch.setattr(cli, "_get_entry_service", lambda _ctx: object())
    monkeypatch.setattr(cli, "launch_tui2", lambda **_: False)

    def fake_main(*, fingerprint=None):
        called["fp"] = fingerprint
        return 0

    monkeypatch.setattr(
        cli,
        "importlib",
        SimpleNamespace(import_module=lambda _: SimpleNamespace(main=fake_main)),
    )
    result = runner.invoke(app, ["--fingerprint", "abc", "tui2"])
    assert result.exit_code == 0
    assert called.get("fp") == "abc"
    assert "falling back to legacy TUI" in result.stdout


def test_tui2_fallback_legacy_strips_subcommand_argv(monkeypatch):
    called = {}
    monkeypatch.setattr(cli, "_get_entry_service", lambda _ctx: object())
    monkeypatch.setattr(cli, "launch_tui2", lambda **_: False)

    def fake_main(*, argv=None, fingerprint=None):
        called["fp"] = fingerprint
        called["argv"] = argv
        return 0

    monkeypatch.setattr(
        cli,
        "importlib",
        SimpleNamespace(import_module=lambda _: SimpleNamespace(main=fake_main)),
    )
    result = runner.invoke(app, ["--fingerprint", "abc", "tui2"])
    assert result.exit_code == 0
    assert called.get("fp") == "abc"
    assert called.get("argv") == []


def test_root_fallback_legacy_when_tui2_unavailable(monkeypatch):
    called = {}
    monkeypatch.setattr(cli, "_get_entry_service", lambda _ctx: object())
    monkeypatch.setattr(cli, "launch_tui2", lambda **_: False)

    def fake_main(*, fingerprint=None):
        called["fp"] = fingerprint
        return 0

    monkeypatch.setattr(
        cli,
        "importlib",
        SimpleNamespace(import_module=lambda _: SimpleNamespace(main=fake_main)),
    )
    result = runner.invoke(app, ["--fingerprint", "abc"])
    assert result.exit_code == 0
    assert called.get("fp") == "abc"
    assert "falling back to legacy TUI" in result.stdout


def test_tui2_preflight_failure_without_fallback(monkeypatch):
    monkeypatch.setattr(
        cli,
        "_get_entry_service",
        lambda _ctx: (_ for _ in ()).throw(RuntimeError("unlock failed")),
    )
    result = runner.invoke(app, ["tui2", "--no-fallback-legacy"])
    assert result.exit_code == 1
    assert "preflight failed" in result.stderr.lower()


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
