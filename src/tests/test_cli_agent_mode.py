import json
import sys
from pathlib import Path
from types import SimpleNamespace

from typer.testing import CliRunner

sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass.cli import app
from seedpass.cli import agent as agent_cli
from seedpass.core.entry_types import EntryType

runner = CliRunner()


def test_agent_policy_show_defaults(monkeypatch, tmp_path):
    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    result = runner.invoke(app, ["agent", "policy-show"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["allow_export_import"] is False
    assert EntryType.PASSWORD.value in payload["allow_kinds"]


def test_agent_policy_set_persists(monkeypatch, tmp_path):
    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    result = runner.invoke(
        app,
        [
            "agent",
            "policy-set",
            "--allow-kind",
            "password",
            "--allow-kind",
            "totp",
            "--deny-private-kind",
            "seed",
            "--allow-export-import",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["allow_kinds"] == ["password", "totp"]
    assert payload["deny_private_reveal"] == ["seed"]
    assert payload["allow_export_import"] is True


def test_agent_init_creates_profile(monkeypatch, tmp_path):
    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    monkeypatch.setenv("SEEDPASS_PASSWORD", "AgentPass123!")
    result = runner.invoke(
        app,
        [
            "agent",
            "init",
            "--seed",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["fingerprint"]
    profile_dir = Path(payload["profile_dir"])
    assert profile_dir.exists()
    assert (profile_dir / "parent_seed.enc").exists()


def test_agent_get_requires_fingerprint(monkeypatch):
    monkeypatch.setenv("SEEDPASS_PASSWORD", "pw")
    result = runner.invoke(app, ["agent", "get", "example"])
    assert result.exit_code == 2


def test_agent_get_password_json(monkeypatch):
    monkeypatch.setenv("SEEDPASS_PASSWORD", "pw")
    monkeypatch.setattr(
        agent_cli,
        "PasswordManager",
        lambda fingerprint, password: SimpleNamespace(
            fingerprint=fingerprint, password=password
        ),
    )

    class DummyEntryService:
        def __init__(self, _pm):
            pass

        def search_entries(self, _q):
            return [(2, "Example", "", "", False, EntryType.PASSWORD)]

        def retrieve_entry(self, _i):
            return {"type": EntryType.PASSWORD.value, "label": "Example", "length": 12}

        def generate_password(self, _length, _index):
            return "secret-pass"

    monkeypatch.setattr(agent_cli, "EntryService", DummyEntryService)
    monkeypatch.setattr(
        agent_cli,
        "_load_policy",
        lambda: {"allow_kinds": ["password"], "deny_private_reveal": []},
    )

    result = runner.invoke(app, ["--fingerprint", "ABC123", "agent", "get", "example"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["fingerprint"] == "ABC123"
    assert payload["secret"] == "secret-pass"
    assert payload["kind"] == "password"


def test_agent_get_denied_by_policy(monkeypatch):
    monkeypatch.setenv("SEEDPASS_PASSWORD", "pw")
    monkeypatch.setattr(
        agent_cli,
        "PasswordManager",
        lambda fingerprint, password: SimpleNamespace(
            fingerprint=fingerprint, password=password
        ),
    )

    class DummyEntryService:
        def __init__(self, _pm):
            pass

        def search_entries(self, _q):
            return [(4, "Seed", "", "", False, EntryType.SEED)]

        def retrieve_entry(self, _i):
            return {"kind": EntryType.SEED.value, "label": "Seed"}

    monkeypatch.setattr(agent_cli, "EntryService", DummyEntryService)
    monkeypatch.setattr(
        agent_cli,
        "_load_policy",
        lambda: {
            "allow_kinds": ["password", "totp", "key_value"],
            "deny_private_reveal": ["seed"],
        },
    )

    result = runner.invoke(app, ["--fingerprint", "ABC123", "agent", "get", "seed"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["status"] == "denied"
    assert payload["reason"] in {"kind_not_allowed", "private_kind_blocked"}
