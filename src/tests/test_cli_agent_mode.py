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


def test_agent_init_requires_password_env(monkeypatch, tmp_path):
    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    monkeypatch.delenv("SEEDPASS_PASSWORD", raising=False)
    result = runner.invoke(
        app,
        [
            "agent",
            "init",
            "--seed",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        ],
    )
    assert result.exit_code == 2
    combined = f"{result.stdout}{result.stderr}"
    assert "Missing password env var" in combined


def test_agent_init_keyring_broker(monkeypatch, tmp_path):
    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    calls = {}

    def fake_resolve_password(**kwargs):
        calls.update(kwargs)
        return "AgentPass123!"

    monkeypatch.setattr(agent_cli, "resolve_broker_password", fake_resolve_password)
    result = runner.invoke(
        app,
        [
            "agent",
            "init",
            "--seed",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "--auth-broker",
            "keyring",
            "--broker-service",
            "seedpass",
            "--broker-account",
            "ci-agent",
        ],
    )
    assert result.exit_code == 0
    assert calls["broker"] == "keyring"
    assert calls["broker_service"] == "seedpass"
    assert calls["broker_account"] == "ci-agent"


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
        lambda **kwargs: {"allow_kinds": ["password"], "deny_private_reveal": []},
    )

    result = runner.invoke(
        app, ["--fingerprint", "ABC123", "agent", "get", "example", "--reveal"]
    )
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
        lambda **kwargs: {
            "allow_kinds": ["password", "totp", "key_value"],
            "deny_private_reveal": ["seed"],
        },
    )

    result = runner.invoke(app, ["--fingerprint", "ABC123", "agent", "get", "seed"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["status"] == "denied"
    assert payload["reason"].startswith("policy_deny:")


def test_agent_get_ambiguous_returns_error_payload(monkeypatch):
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
            return [
                (2, "Example1", "", "", False, EntryType.PASSWORD),
                (3, "Example2", "", "", False, EntryType.PASSWORD),
            ]

    monkeypatch.setattr(agent_cli, "EntryService", DummyEntryService)
    monkeypatch.setattr(
        agent_cli,
        "_load_policy",
        lambda **kwargs: {"allow_kinds": ["password"], "deny_private_reveal": []},
    )

    result = runner.invoke(app, ["--fingerprint", "ABC123", "agent", "get", "example"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["status"] == "error"
    assert payload["reason"] == "ambiguous_or_missing"
    assert payload["match_count"] == 2


def test_agent_get_key_value_json(monkeypatch):
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
            return [(2, "Key", "", "", False, EntryType.KEY_VALUE)]

        def retrieve_entry(self, _i):
            return {"kind": EntryType.KEY_VALUE.value, "label": "Key", "value": "v123"}

    monkeypatch.setattr(agent_cli, "EntryService", DummyEntryService)
    monkeypatch.setattr(
        agent_cli,
        "_load_policy",
        lambda **kwargs: {"allow_kinds": ["key_value"], "deny_private_reveal": []},
    )

    result = runner.invoke(
        app, ["--fingerprint", "ABC123", "agent", "get", "key", "--reveal"]
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["kind"] == "key_value"
    assert payload["secret"] == "v123"


def test_agent_get_safe_output_masks_by_default(monkeypatch):
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
        lambda **kwargs: {
            "version": 1,
            "default_effect": "allow",
            "rules": [],
            "output": {"safe_output_default": True},
            "allow_kinds": ["password"],
            "deny_private_reveal": [],
        },
    )

    result = runner.invoke(app, ["--fingerprint", "ABC123", "agent", "get", "example"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["safe_output"] is True
    assert payload["secret"] != "secret-pass"


def test_agent_token_issue_and_use_limit(monkeypatch, tmp_path):
    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
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
        lambda **kwargs: {
            "version": 1,
            "default_effect": "allow",
            "rules": [],
            "output": {"safe_output_default": False},
            "allow_kinds": ["password"],
            "deny_private_reveal": [],
        },
    )

    issue = runner.invoke(
        app,
        [
            "agent",
            "token-issue",
            "--name",
            "ci-agent",
            "--scope",
            "read",
            "--kind",
            "password",
            "--uses",
            "1",
            "--ttl",
            "600",
        ],
    )
    assert issue.exit_code == 0
    issued_payload = json.loads(issue.stdout)
    token = issued_payload["token"]

    first = runner.invoke(
        app,
        [
            "--fingerprint",
            "ABC123",
            "agent",
            "get",
            "example",
            "--token",
            token,
            "--reveal",
        ],
    )
    assert first.exit_code == 0
    first_payload = json.loads(first.stdout)
    assert first_payload["status"] == "ok"
    assert first_payload["token_uses_remaining"] == 0

    second = runner.invoke(
        app,
        [
            "--fingerprint",
            "ABC123",
            "agent",
            "get",
            "example",
            "--token",
            token,
            "--reveal",
        ],
    )
    assert second.exit_code == 1
    second_payload = json.loads(second.stdout)
    assert second_payload["status"] == "denied"
    assert second_payload["reason"] == "token_exhausted"


def test_agent_get_unsupported_kind_payload(monkeypatch):
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
            return [(4, "SSH", "", "", False, EntryType.SSH)]

        def retrieve_entry(self, _i):
            return {"kind": EntryType.SSH.value, "label": "SSH"}

    monkeypatch.setattr(agent_cli, "EntryService", DummyEntryService)
    monkeypatch.setattr(
        agent_cli,
        "_load_policy",
        lambda **kwargs: {"allow_kinds": ["ssh"], "deny_private_reveal": []},
    )

    result = runner.invoke(app, ["--fingerprint", "ABC123", "agent", "get", "ssh"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["status"] == "error"
    assert payload["reason"] == "unsupported_kind_for_agent_get"


def test_agent_policy_show_invalid_json(monkeypatch, tmp_path):
    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    (tmp_path / "agent_policy.json").write_text("{", encoding="utf-8")
    result = runner.invoke(app, ["agent", "policy-show"])
    assert result.exit_code == 2
    combined = f"{result.stdout}{result.stderr}"
    assert "not valid JSON" in combined


def test_agent_get_denied_when_policy_invalid(monkeypatch, tmp_path):
    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    (tmp_path / "agent_policy.json").write_text("{", encoding="utf-8")
    monkeypatch.setenv("SEEDPASS_PASSWORD", "pw")
    result = runner.invoke(app, ["--fingerprint", "ABC123", "agent", "get", "example"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["status"] == "denied"
    assert payload["reason"] == "invalid_policy"


def test_agent_get_keyring_defaults_account_to_fingerprint(monkeypatch):
    calls = {}
    monkeypatch.setattr(
        agent_cli,
        "resolve_broker_password",
        lambda **kwargs: calls.update(kwargs) or "pw",
    )
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
        lambda **kwargs: {
            "version": 1,
            "default_effect": "allow",
            "rules": [],
            "output": {"safe_output_default": False},
            "allow_kinds": ["password"],
            "deny_private_reveal": [],
        },
    )

    result = runner.invoke(
        app,
        [
            "--fingerprint",
            "ABC123",
            "agent",
            "get",
            "example",
            "--auth-broker",
            "keyring",
            "--broker-service",
            "seedpass",
            "--reveal",
        ],
    )
    assert result.exit_code == 0
    assert calls["broker"] == "keyring"
    assert calls["broker_account"] == "ABC123"


def test_agent_bootstrap_context(monkeypatch, tmp_path):
    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    result = runner.invoke(app, ["--fingerprint", "ABC123", "agent", "bootstrap-context"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["fingerprint"] == "ABC123"
    assert payload["policy"]["status"] == "ok"
    assert "supported" in payload["auth_brokers"]
    assert "agent token-issue" in payload["commands"]["tokens"]


def test_agent_bootstrap_context_invalid_policy(monkeypatch, tmp_path):
    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    (tmp_path / "agent_policy.json").write_text("{", encoding="utf-8")
    result = runner.invoke(app, ["agent", "bootstrap-context"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["policy"]["status"] == "invalid"


def test_agent_posture_check_clean(monkeypatch, tmp_path):
    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    result = runner.invoke(app, ["agent", "posture-check"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["finding_count"] == 0
    assert payload["highest_severity"] == "info"


def test_agent_posture_check_invalid_policy_fails(monkeypatch, tmp_path):
    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    (tmp_path / "agent_policy.json").write_text("{", encoding="utf-8")
    result = runner.invoke(app, ["agent", "posture-check", "--fail-on", "critical"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["policy_status"] == "invalid"
    assert payload["highest_severity"] == "critical"
    assert any(f["id"] == "policy_invalid" for f in payload["findings"])


def test_agent_posture_check_high_risk_policy(monkeypatch, tmp_path):
    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    policy = {
        "version": 1,
        "default_effect": "allow",
        "rules": [],
        "output": {"safe_output_default": False, "redact_fields": ["secret"]},
        "export": {"allow_full_vault": True},
        "allow_export_import": True,
        "allow_kinds": ["password"],
        "deny_private_reveal": [],
    }
    (tmp_path / "agent_policy.json").write_text(json.dumps(policy), encoding="utf-8")
    result = runner.invoke(app, ["agent", "posture-check", "--fail-on", "high"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    ids = {f["id"] for f in payload["findings"]}
    assert "policy_default_allow" in ids
    assert "safe_output_disabled" in ids
    assert "export_import_allowed" in ids
