import json
import sys
from datetime import datetime, timedelta, timezone
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


def test_agent_policy_lint_file(monkeypatch, tmp_path):
    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    candidate = tmp_path / "candidate_policy.json"
    candidate.write_text(
        json.dumps(
            {
                "version": 1,
                "default_effect": "deny",
                "rules": [
                    {
                        "id": "allow_read_pw",
                        "effect": "allow",
                        "operations": ["read"],
                        "kinds": ["password"],
                        "label_regex": ".*",
                        "path_regex": "^entry/.*$",
                        "fields": ["secret", "label", "kind"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    result = runner.invoke(app, ["agent", "policy-lint", "--file", str(candidate)])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["path"] == str(candidate)
    assert payload["policy_stamp"]
    assert payload["policy_hash"]


def test_agent_policy_review_and_apply_risk_gate(monkeypatch, tmp_path):
    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    candidate = tmp_path / "risky_policy.json"
    candidate.write_text(
        json.dumps(
            {
                "version": 1,
                "default_effect": "allow",
                "rules": [],
                "output": {"safe_output_default": False, "redact_fields": []},
                "export": {"allow_full_vault": True},
            }
        ),
        encoding="utf-8",
    )

    review = runner.invoke(app, ["agent", "policy-review", "--file", str(candidate)])
    assert review.exit_code == 0
    review_payload = json.loads(review.stdout)
    assert review_payload["changed"] is True
    assert review_payload["diff_summary"]["default_effect_changed"] is True
    assert review_payload["risky_finding_count"] >= 1

    denied = runner.invoke(app, ["agent", "policy-apply", "--file", str(candidate)])
    assert denied.exit_code == 1
    denied_payload = json.loads(denied.stdout)
    assert denied_payload["status"] == "denied"
    assert denied_payload["reason"] == "risky_policy_change_requires_allow_risky"

    allowed = runner.invoke(
        app, ["agent", "policy-apply", "--file", str(candidate), "--allow-risky"]
    )
    assert allowed.exit_code == 0
    allowed_payload = json.loads(allowed.stdout)
    assert allowed_payload["status"] == "ok"
    assert allowed_payload["applied"] is True

    shown = runner.invoke(app, ["agent", "policy-show"])
    assert shown.exit_code == 0
    shown_policy = json.loads(shown.stdout)
    assert shown_policy["default_effect"] == "allow"


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
    assert "next_steps" in payload
    assert any("seedpass capabilities" in step for step in payload["next_steps"])
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


def test_agent_get_private_kind_requires_approval(monkeypatch, tmp_path):
    import seedpass.core.agent_approval as approval_core
    import seedpass.core.agent_secret_isolation as isolation_core

    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    monkeypatch.setattr(approval_core, "APP_DIR", tmp_path)
    monkeypatch.setattr(isolation_core, "APP_DIR", tmp_path)
    monkeypatch.setenv("SEEDPASS_PASSWORD", "pw")

    entry_mgr = SimpleNamespace(
        get_ssh_key_pair=lambda idx, seed: ("SSH_PRIVATE", "SSH_PUBLIC")
    )
    monkeypatch.setattr(
        agent_cli,
        "PasswordManager",
        lambda fingerprint, password: SimpleNamespace(
            fingerprint=fingerprint,
            password=password,
            parent_seed="seed",
            entry_manager=entry_mgr,
        ),
    )

    class DummyEntryService:
        def __init__(self, _pm):
            pass

        def search_entries(self, _q):
            return [(7, "SSHKey", "", "", False, EntryType.SSH)]

        def retrieve_entry(self, _i):
            return {"kind": EntryType.SSH.value, "label": "SSHKey"}

    monkeypatch.setattr(agent_cli, "EntryService", DummyEntryService)
    monkeypatch.setattr(
        agent_cli,
        "_load_policy",
        lambda **kwargs: {
            "version": 1,
            "default_effect": "deny",
            "rules": [
                {
                    "id": "allow_ssh_read",
                    "effect": "allow",
                    "operations": ["read"],
                    "kinds": ["ssh"],
                    "label_regex": ".*",
                    "path_regex": "^entry/.*$",
                    "fields": ["secret"],
                }
            ],
            "approvals": {"require_for": ["private_key_retrieval"]},
            "secret_isolation": {"enabled": False},
            "output": {"safe_output_default": False, "redact_fields": ["secret"]},
            "export": {"allow_full_vault": False},
            "allow_kinds": ["ssh"],
            "deny_private_reveal": [],
            "allow_export_import": False,
        },
    )

    denied = runner.invoke(
        app,
        ["--fingerprint", "ABC123", "agent", "get", "sshkey", "--reveal"],
    )
    assert denied.exit_code == 1
    denied_payload = json.loads(denied.stdout)
    assert denied_payload["status"] == "denied"
    assert denied_payload["reason"] == "policy_deny:approval_required"

    approval = approval_core.issue_approval(
        action="private_key_retrieval",
        ttl_seconds=300,
        uses=1,
        resource="entry:ssh:7",
    )
    allowed = runner.invoke(
        app,
        [
            "--fingerprint",
            "ABC123",
            "agent",
            "get",
            "sshkey",
            "--reveal",
            "--approval-id",
            approval["id"],
        ],
    )
    assert allowed.exit_code == 0
    allowed_payload = json.loads(allowed.stdout)
    assert allowed_payload["status"] == "ok"
    assert allowed_payload["kind"] == "ssh"
    assert allowed_payload["secret"] == "SSH_PRIVATE"


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
    assert issued_payload["identity_id"] == "default-agent"

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


def test_agent_document_import_with_token_scope(monkeypatch, tmp_path):
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

        def import_document_file(self, file_path, **kwargs):
            assert str(file_path).endswith("notes.md")
            assert kwargs["label"] == "My Notes"
            assert kwargs["notes"] == "imported"
            assert kwargs["tags"] == ["work"]
            assert kwargs["archived"] is False
            return 12

        def retrieve_entry(self, _i):
            return {
                "kind": EntryType.DOCUMENT.value,
                "label": "My Notes",
                "file_type": "md",
            }

    monkeypatch.setattr(agent_cli, "EntryService", DummyEntryService)
    monkeypatch.setattr(
        agent_cli,
        "_load_policy",
        lambda **kwargs: {
            "version": 1,
            "default_effect": "deny",
            "rules": [
                {
                    "id": "allow_doc_read",
                    "effect": "allow",
                    "operations": ["read"],
                    "kinds": ["document"],
                    "label_regex": ".*",
                    "path_regex": "^entry/.*$",
                    "fields": ["secret"],
                }
            ],
            "approvals": {"require_for": []},
            "output": {"safe_output_default": True, "redact_fields": ["secret"]},
            "export": {"allow_full_vault": True},
            "secret_isolation": {
                "enabled": False,
                "high_risk_kinds": [],
                "unlock_ttl_sec": 300,
            },
            "allow_kinds": ["document"],
            "deny_private_reveal": [],
            "allow_export_import": True,
        },
    )

    source = tmp_path / "notes.md"
    source.write_text("# hello\n", encoding="utf-8")

    issue = runner.invoke(
        app,
        [
            "agent",
            "token-issue",
            "--name",
            "doc-import",
            "--scope",
            "import",
            "--kind",
            "document",
            "--uses",
            "1",
            "--ttl",
            "600",
        ],
    )
    assert issue.exit_code == 0
    token = json.loads(issue.stdout)["token"]

    result = runner.invoke(
        app,
        [
            "--fingerprint",
            "ABC123",
            "agent",
            "document-import",
            "--file",
            str(source),
            "--label",
            "My Notes",
            "--notes",
            "imported",
            "--tag",
            "work",
            "--token",
            token,
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["index"] == 12
    assert payload["kind"] == "document"
    assert payload["file_type"] == "md"
    assert payload["token_uses_remaining"] == 0


def test_agent_document_export_with_token_scope(monkeypatch, tmp_path):
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

        def retrieve_entry(self, _i):
            return {"kind": EntryType.DOCUMENT.value, "label": "Spec"}

        def export_document_file(self, _entry_id, out, **kwargs):
            assert out == str(tmp_path)
            assert kwargs["overwrite"] is True
            return tmp_path / "Spec.md"

    monkeypatch.setattr(agent_cli, "EntryService", DummyEntryService)
    monkeypatch.setattr(
        agent_cli,
        "_load_policy",
        lambda **kwargs: {
            "version": 1,
            "default_effect": "deny",
            "rules": [
                {
                    "id": "allow_doc_read",
                    "effect": "allow",
                    "operations": ["read"],
                    "kinds": ["document"],
                    "label_regex": ".*",
                    "path_regex": "^entry/.*$",
                    "fields": ["secret"],
                }
            ],
            "approvals": {"require_for": []},
            "output": {"safe_output_default": True, "redact_fields": ["secret"]},
            "export": {"allow_full_vault": True},
            "secret_isolation": {
                "enabled": False,
                "high_risk_kinds": [],
                "unlock_ttl_sec": 300,
            },
            "allow_kinds": ["document"],
            "deny_private_reveal": [],
            "allow_export_import": True,
        },
    )

    issue = runner.invoke(
        app,
        [
            "agent",
            "token-issue",
            "--name",
            "doc-export",
            "--scope",
            "export",
            "--kind",
            "document",
            "--uses",
            "1",
            "--ttl",
            "600",
        ],
    )
    assert issue.exit_code == 0
    token = json.loads(issue.stdout)["token"]

    result = runner.invoke(
        app,
        [
            "--fingerprint",
            "ABC123",
            "agent",
            "document-export",
            "--entry-id",
            "4",
            "--out",
            str(tmp_path),
            "--overwrite",
            "--token",
            token,
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["index"] == 4
    assert payload["kind"] == "document"
    assert payload["output_path"] == str(tmp_path / "Spec.md")
    assert payload["token_uses_remaining"] == 0


def test_agent_identity_create_list_revoke(monkeypatch, tmp_path):
    import seedpass.core.agent_identity as identity_core

    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    monkeypatch.setattr(identity_core, "APP_DIR", tmp_path)
    created = runner.invoke(
        app,
        [
            "agent",
            "identity-create",
            "--id",
            "ci-bot",
            "--owner",
            "platform",
            "--policy-binding",
            "default",
            "--rotation-days",
            "14",
        ],
    )
    assert created.exit_code == 0
    created_payload = json.loads(created.stdout)
    assert created_payload["status"] == "ok"
    assert created_payload["identity"]["id"] == "ci-bot"

    listed = runner.invoke(app, ["agent", "identity-list"])
    assert listed.exit_code == 0
    listed_payload = json.loads(listed.stdout)
    assert any(v["id"] == "ci-bot" for v in listed_payload["identities"])

    revoked = runner.invoke(app, ["agent", "identity-revoke", "--", "ci-bot"])
    assert revoked.exit_code == 0
    revoked_payload = json.loads(revoked.stdout)
    assert revoked_payload["status"] == "ok"
    assert revoked_payload["id"] == "ci-bot"


def test_agent_token_denied_when_identity_revoked(monkeypatch, tmp_path):
    import seedpass.core.agent_identity as identity_core

    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    monkeypatch.setattr(identity_core, "APP_DIR", tmp_path)
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

    created = runner.invoke(
        app,
        ["agent", "identity-create", "--id", "revoked-agent", "--owner", "secops"],
    )
    assert created.exit_code == 0

    issue = runner.invoke(
        app,
        [
            "agent",
            "token-issue",
            "--name",
            "revoked-agent-token",
            "--scope",
            "read",
            "--kind",
            "password",
            "--uses",
            "2",
            "--ttl",
            "600",
            "--identity-id",
            "revoked-agent",
        ],
    )
    assert issue.exit_code == 0
    token = json.loads(issue.stdout)["token"]

    revoke = runner.invoke(app, ["agent", "identity-revoke", "--", "revoked-agent"])
    assert revoke.exit_code == 0

    denied = runner.invoke(
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
    assert denied.exit_code == 1
    denied_payload = json.loads(denied.stdout)
    assert denied_payload["status"] == "denied"
    assert denied_payload["reason"] == "token_identity_revoked"


def test_agent_token_denied_when_identity_missing(monkeypatch, tmp_path):
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

    raw_token, record = agent_cli._issue_token_record(
        "legacy-no-identity",
        600,
        ["read"],
        ["password"],
        ".*",
        1,
        "",
    )
    agent_cli._save_token_store(
        {"version": agent_cli.TOKEN_STORE_VERSION, "tokens": [record]}
    )

    denied = runner.invoke(
        app,
        [
            "--fingerprint",
            "ABC123",
            "agent",
            "get",
            "example",
            "--token",
            raw_token,
            "--reveal",
        ],
    )
    assert denied.exit_code == 1
    denied_payload = json.loads(denied.stdout)
    assert denied_payload["status"] == "denied"
    assert denied_payload["reason"] == "token_identity_missing"


def test_agent_job_run_rejects_env_broker_by_default(monkeypatch):
    result = runner.invoke(
        app,
        [
            "--fingerprint",
            "ABC123",
            "agent",
            "job-run",
            "example",
            "--auth-broker",
            "env",
        ],
    )
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["status"] == "denied"
    assert payload["reason"] == "unsafe_broker_for_job"
    assert "keyring" in payload["allowed_brokers"]


def test_agent_job_template_cron_json(monkeypatch):
    result = runner.invoke(
        app,
        [
            "--fingerprint",
            "ABC123",
            "agent",
            "job-template",
            "example",
            "--mode",
            "cron",
            "--auth-broker",
            "keyring",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["mode"] == "cron"
    assert "agent job-run example" in payload["command"]
    assert "SEEDPASS_PASSWORD" not in payload["command"]
    assert "cron_line" in payload


def test_agent_job_template_systemd_text(monkeypatch):
    result = runner.invoke(
        app,
        [
            "--fingerprint",
            "ABC123",
            "agent",
            "job-template",
            "example",
            "--mode",
            "systemd",
            "--format",
            "text",
            "--schedule",
            "*:0/15",
            "--unit-name",
            "seedpass-nightly",
        ],
    )
    assert result.exit_code == 0
    assert "Agent Job Template (systemd)" in result.stdout
    assert (
        "ExecStart=seedpass --fingerprint ABC123 agent job-run example" in result.stdout
    )
    assert "[Timer]" in result.stdout


def test_agent_job_profile_lifecycle(monkeypatch, tmp_path):
    import seedpass.core.agent_job as job_core

    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    monkeypatch.setattr(job_core, "APP_DIR", tmp_path)

    created = runner.invoke(
        app,
        [
            "--fingerprint",
            "ABC123",
            "agent",
            "job-profile-create",
            "--id",
            "nightly-read",
            "--query",
            "example",
            "--auth-broker",
            "keyring",
            "--schedule",
            "*/30 * * * *",
            "--description",
            "nightly pull",
        ],
    )
    assert created.exit_code == 0
    created_payload = json.loads(created.stdout)
    assert created_payload["status"] == "ok"
    assert created_payload["job_profile"]["id"] == "nightly-read"

    listed = runner.invoke(app, ["agent", "job-profile-list"])
    assert listed.exit_code == 0
    listed_payload = json.loads(listed.stdout)
    assert any(v["id"] == "nightly-read" for v in listed_payload["job_profiles"])

    calls = {}

    def fake_job_run(**kwargs):
        calls.update(kwargs)

    monkeypatch.setattr(agent_cli, "agent_job_run", fake_job_run)
    ran = runner.invoke(
        app,
        ["--fingerprint", "ABC123", "agent", "job-profile-run", "nightly-read"],
    )
    assert ran.exit_code == 0
    assert calls["query"] == "example"
    assert calls["auth_broker"] == "keyring"

    revoked = runner.invoke(app, ["agent", "job-profile-revoke", "--", "nightly-read"])
    assert revoked.exit_code == 0
    revoked_payload = json.loads(revoked.stdout)
    assert revoked_payload["status"] == "ok"

    denied = runner.invoke(
        app,
        ["--fingerprint", "ABC123", "agent", "job-profile-run", "nightly-read"],
    )
    assert denied.exit_code == 1
    denied_payload = json.loads(denied.stdout)
    assert denied_payload["reason"] == "job_profile_not_found"


def test_agent_job_profile_run_fingerprint_mismatch(monkeypatch, tmp_path):
    import seedpass.core.agent_job as job_core

    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    monkeypatch.setattr(job_core, "APP_DIR", tmp_path)
    created = runner.invoke(
        app,
        [
            "--fingerprint",
            "ABC123",
            "agent",
            "job-profile-create",
            "--id",
            "fp-bound",
            "--query",
            "example",
        ],
    )
    assert created.exit_code == 0

    mismatch = runner.invoke(
        app,
        ["--fingerprint", "XYZ999", "agent", "job-profile-run", "fp-bound"],
    )
    assert mismatch.exit_code == 1
    payload = json.loads(mismatch.stdout)
    assert payload["reason"] == "job_profile_fingerprint_mismatch"


def test_agent_job_profile_run_policy_mismatch(monkeypatch, tmp_path):
    import seedpass.core.agent_job as job_core

    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    monkeypatch.setattr(job_core, "APP_DIR", tmp_path)
    created = runner.invoke(
        app,
        [
            "--fingerprint",
            "ABC123",
            "agent",
            "job-profile-create",
            "--id",
            "policy-bound",
            "--query",
            "example",
        ],
    )
    assert created.exit_code == 0

    (tmp_path / "agent_policy.json").write_text(
        json.dumps({"default_effect": "allow", "rules": []}), encoding="utf-8"
    )
    denied = runner.invoke(
        app,
        ["--fingerprint", "ABC123", "agent", "job-profile-run", "policy-bound"],
    )
    assert denied.exit_code == 1
    denied_payload = json.loads(denied.stdout)
    assert denied_payload["reason"] == "job_profile_policy_mismatch"

    calls = {}

    def fake_job_run(**kwargs):
        calls.update(kwargs)

    monkeypatch.setattr(agent_cli, "agent_job_run", fake_job_run)
    allowed = runner.invoke(
        app,
        [
            "--fingerprint",
            "ABC123",
            "agent",
            "job-profile-run",
            "policy-bound",
            "--allow-policy-drift",
        ],
    )
    assert allowed.exit_code == 0
    assert calls["query"] == "example"


def test_agent_job_profile_run_host_mismatch(monkeypatch, tmp_path):
    import seedpass.core.agent_job as job_core

    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    monkeypatch.setattr(job_core, "APP_DIR", tmp_path)
    created = runner.invoke(
        app,
        [
            "--fingerprint",
            "ABC123",
            "agent",
            "job-profile-create",
            "--id",
            "host-bound",
            "--query",
            "example",
            "--bind-host",
            "other-host",
        ],
    )
    assert created.exit_code == 0
    denied = runner.invoke(
        app,
        ["--fingerprint", "ABC123", "agent", "job-profile-run", "host-bound"],
    )
    assert denied.exit_code == 1
    denied_payload = json.loads(denied.stdout)
    assert denied_payload["reason"] == "job_profile_host_mismatch"


def test_agent_job_profile_check_detects_policy_drift(monkeypatch, tmp_path):
    import seedpass.core.agent_job as job_core

    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    monkeypatch.setattr(job_core, "APP_DIR", tmp_path)
    created = runner.invoke(
        app,
        [
            "--fingerprint",
            "ABC123",
            "agent",
            "job-profile-create",
            "--id",
            "drift-job",
            "--query",
            "example",
        ],
    )
    assert created.exit_code == 0
    (tmp_path / "agent_policy.json").write_text(
        json.dumps({"default_effect": "allow", "rules": []}), encoding="utf-8"
    )
    checked = runner.invoke(
        app, ["agent", "job-profile-check", "--strict-exit", "--max-age-days", "1"]
    )
    assert checked.exit_code == 1
    payload = json.loads(checked.stdout)
    ids = {v["id"] for v in payload["findings"]}
    assert "job_profile_policy_mismatch" in ids


def test_agent_recovery_split_and_recover_roundtrip():
    secret = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    split = runner.invoke(
        app,
        [
            "agent",
            "recovery-split",
            "--secret",
            secret,
            "--shares",
            "5",
            "--threshold",
            "3",
            "--label",
            "seed-recovery",
        ],
    )
    assert split.exit_code == 0
    split_payload = json.loads(split.stdout)
    assert split_payload["status"] == "ok"
    shares = split_payload["shares"]
    assert len(shares) == 5

    recovered = runner.invoke(
        app,
        [
            "agent",
            "recovery-recover",
            "--share",
            shares[0],
            "--share",
            shares[1],
            "--share",
            shares[2],
            "--reveal",
        ],
    )
    assert recovered.exit_code == 0
    recovered_payload = json.loads(recovered.stdout)
    assert recovered_payload["status"] == "ok"
    assert recovered_payload["secret"] == secret


def test_agent_recovery_recover_insufficient_shares():
    split = runner.invoke(
        app,
        [
            "agent",
            "recovery-split",
            "--secret",
            "seed words",
            "--shares",
            "4",
            "--threshold",
            "3",
        ],
    )
    assert split.exit_code == 0
    shares = json.loads(split.stdout)["shares"]
    recovered = runner.invoke(
        app,
        [
            "agent",
            "recovery-recover",
            "--share",
            shares[0],
            "--share",
            shares[1],
            "--reveal",
        ],
    )
    assert recovered.exit_code == 1
    payload = json.loads(recovered.stdout)
    assert payload["status"] == "error"
    assert payload["reason"] == "insufficient_shares"


def test_agent_recovery_drill_records_and_strict_exit(monkeypatch, tmp_path):
    import seedpass.core.agent_recovery as recovery_core

    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    monkeypatch.setattr(recovery_core, "APP_DIR", tmp_path)
    missing = tmp_path / "missing.enc"
    warned = runner.invoke(
        app,
        [
            "--fingerprint",
            "ABC123",
            "agent",
            "recovery-drill",
            "--backup-path",
            str(missing),
        ],
    )
    assert warned.exit_code == 0
    warned_payload = json.loads(warned.stdout)
    assert warned_payload["report"]["status"] == "warning"

    strict = runner.invoke(
        app,
        [
            "--fingerprint",
            "ABC123",
            "agent",
            "recovery-drill",
            "--backup-path",
            str(missing),
            "--strict-exit",
        ],
    )
    assert strict.exit_code == 1

    listed = runner.invoke(app, ["agent", "recovery-drill-list", "--limit", "5"])
    assert listed.exit_code == 0
    listed_payload = json.loads(listed.stdout)
    assert listed_payload["count"] >= 1


def test_agent_high_risk_unlock_required_for_private_kind(monkeypatch, tmp_path):
    import seedpass.core.agent_secret_isolation as isolation_core

    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    monkeypatch.setattr(isolation_core, "APP_DIR", tmp_path)
    monkeypatch.setenv("SEEDPASS_PASSWORD", "pw")
    monkeypatch.setenv("HR_FACTOR", "factor-123")

    entry_mgr = SimpleNamespace(
        get_ssh_key_pair=lambda idx, seed: ("SSH_PRIVATE", "SSH_PUBLIC")
    )
    monkeypatch.setattr(
        agent_cli,
        "PasswordManager",
        lambda fingerprint, password: SimpleNamespace(
            fingerprint=fingerprint,
            password=password,
            parent_seed="seed",
            entry_manager=entry_mgr,
        ),
    )

    class DummyEntryService:
        def __init__(self, _pm):
            pass

        def search_entries(self, _q):
            return [(7, "SSHKey", "", "", False, EntryType.SSH)]

        def retrieve_entry(self, _i):
            return {"kind": EntryType.SSH.value, "label": "SSHKey"}

    monkeypatch.setattr(agent_cli, "EntryService", DummyEntryService)
    monkeypatch.setattr(
        agent_cli,
        "_load_policy",
        lambda **kwargs: {
            "version": 1,
            "default_effect": "deny",
            "rules": [
                {
                    "id": "allow_ssh_read",
                    "effect": "allow",
                    "operations": ["read"],
                    "kinds": ["ssh"],
                    "label_regex": ".*",
                    "path_regex": "^entry/.*$",
                    "fields": ["secret"],
                }
            ],
            "approvals": {"require_for": []},
            "secret_isolation": {
                "enabled": True,
                "high_risk_kinds": ["ssh"],
                "unlock_ttl_sec": 300,
            },
            "output": {"safe_output_default": False, "redact_fields": ["secret"]},
            "export": {"allow_full_vault": False},
            "allow_kinds": ["ssh"],
            "deny_private_reveal": [],
            "allow_export_import": False,
        },
    )

    denied = runner.invoke(
        app,
        ["--fingerprint", "ABC123", "agent", "get", "sshkey", "--reveal"],
    )
    assert denied.exit_code == 1
    denied_payload = json.loads(denied.stdout)
    assert denied_payload["status"] == "denied"
    assert denied_payload["reason"] == "policy_deny:high_risk_locked"

    set_factor = runner.invoke(
        app,
        ["agent", "high-risk-factor-set", "--factor-env", "HR_FACTOR"],
    )
    assert set_factor.exit_code == 0

    unlock = runner.invoke(
        app,
        [
            "--fingerprint",
            "ABC123",
            "agent",
            "high-risk-unlock",
            "--factor-env",
            "HR_FACTOR",
            "--ttl",
            "120",
        ],
    )
    assert unlock.exit_code == 0
    unlock_payload = json.loads(unlock.stdout)
    assert unlock_payload["status"] == "ok"

    allowed = runner.invoke(
        app,
        ["--fingerprint", "ABC123", "agent", "get", "sshkey", "--reveal"],
    )
    assert allowed.exit_code == 0
    allowed_payload = json.loads(allowed.stdout)
    assert allowed_payload["status"] == "ok"
    assert allowed_payload["secret"] == "SSH_PRIVATE"

    locked = runner.invoke(
        app,
        ["--fingerprint", "ABC123", "agent", "high-risk-lock"],
    )
    assert locked.exit_code == 0

    denied_again = runner.invoke(
        app,
        ["--fingerprint", "ABC123", "agent", "get", "sshkey", "--reveal"],
    )
    assert denied_again.exit_code == 1
    denied_again_payload = json.loads(denied_again.stdout)
    assert denied_again_payload["reason"] == "policy_deny:high_risk_locked"


def test_agent_get_private_kind_without_approval_denied(monkeypatch, tmp_path):
    import seedpass.core.agent_secret_isolation as isolation_core

    monkeypatch.setenv("SEEDPASS_PASSWORD", "pw")
    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    monkeypatch.setattr(isolation_core, "APP_DIR", tmp_path)
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
        lambda **kwargs: {
            "allow_kinds": ["ssh"],
            "deny_private_reveal": [],
            "secret_isolation": {"enabled": False},
        },
    )

    result = runner.invoke(app, ["--fingerprint", "ABC123", "agent", "get", "ssh"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["status"] == "denied"
    assert payload["reason"] == "policy_deny:approval_required"


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
    result = runner.invoke(
        app, ["--fingerprint", "ABC123", "agent", "bootstrap-context"]
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["fingerprint"] == "ABC123"
    assert payload["policy"]["status"] == "ok"
    assert "supported" in payload["auth_brokers"]
    assert "agent token-issue" in payload["commands"]["tokens"]
    assert "agent policy-review" in payload["commands"]["policy"]
    assert "agent policy-apply" in payload["commands"]["policy"]
    assert "agent approval-issue" in payload["commands"]["approvals"]
    assert "agent lease-consume" in payload["commands"]["leases"]
    assert "agent job-run" in payload["commands"]["automation"]
    assert "agent job-profile-check" in payload["commands"]["automation"]
    assert "agent recovery-split" in payload["commands"]["recovery"]
    assert "agent identity-create" in payload["commands"]["identities"]
    assert "agent high-risk-unlock" in payload["commands"]["secret_isolation"]
    assert "agent export-check" in payload["commands"]["export_controls"]
    assert "agent document-export <query>" in payload["commands"]["document_io"]
    assert "agent posture-check" in payload["commands"]["posture"]
    assert "agent posture-remediate" in payload["commands"]["posture"]
    assert "identities" in payload
    assert "export" in payload["policy"]["approvals_required_for"]


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


def test_agent_approval_issue_list_and_revoke(monkeypatch, tmp_path):
    import seedpass.core.agent_approval as approval_core

    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    monkeypatch.setattr(approval_core, "APP_DIR", tmp_path)

    issue = runner.invoke(
        app,
        [
            "agent",
            "approval-issue",
            "--action",
            "export",
            "--ttl",
            "600",
            "--uses",
            "2",
            "--resource",
            "vault:full",
            "--issued-by",
            "test-suite",
        ],
    )
    assert issue.exit_code == 0
    issue_payload = json.loads(issue.stdout)
    assert issue_payload["status"] == "ok"
    approval_id = issue_payload["approval"]["id"]
    assert issue_payload["approval"]["uses_remaining"] == 2

    listed = runner.invoke(app, ["agent", "approval-list"])
    assert listed.exit_code == 0
    listed_payload = json.loads(listed.stdout)
    assert any(a["id"] == approval_id for a in listed_payload["approvals"])

    revoked = runner.invoke(app, ["agent", "approval-revoke", "--", approval_id])
    assert revoked.exit_code == 0
    revoked_payload = json.loads(revoked.stdout)
    assert revoked_payload["status"] == "ok"
    assert revoked_payload["approval_id"] == approval_id


def test_agent_secret_lease_issue_consume_and_exhaust(monkeypatch, tmp_path):
    import seedpass.core.agent_secret_lease as lease_core

    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    monkeypatch.setattr(lease_core, "APP_DIR", tmp_path)
    monkeypatch.setenv("SEEDPASS_PASSWORD", "pw")

    monkeypatch.setattr(
        agent_cli,
        "PasswordManager",
        lambda fingerprint, password: SimpleNamespace(
            fingerprint=fingerprint,
            password=password,
            entry_manager=SimpleNamespace(
                retrieve_entry=lambda _i: {
                    "type": EntryType.PASSWORD.value,
                    "kind": EntryType.PASSWORD.value,
                    "label": "Example",
                    "length": 12,
                }
            ),
        ),
    )
    monkeypatch.setattr(
        agent_cli,
        "_resolve_secret_for_kind",
        lambda pm, service, entry, index: "secret-pass",
    )

    class DummyEntryService:
        def __init__(self, _pm):
            pass

        def search_entries(self, _q):
            return [(2, "Example", "", "", False, EntryType.PASSWORD)]

        def retrieve_entry(self, _i):
            return {
                "type": EntryType.PASSWORD.value,
                "kind": "password",
                "label": "Example",
                "length": 12,
            }

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

    issued = runner.invoke(
        app,
        [
            "--fingerprint",
            "ABC123",
            "agent",
            "get",
            "example",
            "--lease-only",
            "--ttl",
            "120",
            "--lease-uses",
            "1",
        ],
    )
    assert issued.exit_code == 0
    issued_payload = json.loads(issued.stdout)
    assert issued_payload["status"] == "ok"
    assert issued_payload["mode"] == "lease_issued"
    lease_id = issued_payload["lease_id"]

    first = runner.invoke(
        app,
        [
            "--fingerprint",
            "ABC123",
            "agent",
            "lease-consume",
            "--reveal",
            "--",
            lease_id,
        ],
    )
    assert first.exit_code == 0
    first_payload = json.loads(first.stdout)
    assert first_payload["status"] == "ok"
    assert first_payload["secret"] == "secret-pass"
    assert first_payload["lease_uses_remaining"] == 0

    second = runner.invoke(
        app,
        [
            "--fingerprint",
            "ABC123",
            "agent",
            "lease-consume",
            "--reveal",
            "--",
            lease_id,
        ],
    )
    assert second.exit_code == 1
    second_payload = json.loads(second.stdout)
    assert second_payload["status"] == "denied"
    assert second_payload["reason"] == "lease_exhausted"


def test_agent_lease_consume_hydrates_partitioned_private_entry(monkeypatch, tmp_path):
    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    monkeypatch.setenv("SEEDPASS_PASSWORD", "pw")

    lease = {
        "id": "lease-1",
        "fingerprint": "ABC123",
        "index": 7,
        "kind": EntryType.SSH.value,
        "uses_remaining": 0,
    }
    monkeypatch.setattr(
        agent_cli,
        "consume_lease",
        lambda lease_id, fingerprint=None: (True, "ok", lease),
    )
    monkeypatch.setattr(
        agent_cli,
        "PasswordManager",
        lambda fingerprint, password: SimpleNamespace(
            fingerprint=fingerprint,
            password=password,
            fingerprint_dir=str(tmp_path / "fp"),
            parent_seed="seed",
            entry_manager=SimpleNamespace(),
        ),
    )

    class DummyEntryService:
        def __init__(self, _pm):
            pass

        def retrieve_entry(self, _i):
            return {
                "kind": EntryType.SSH.value,
                "label": "SSHKey",
                "partition": "high_risk",
            }

    monkeypatch.setattr(agent_cli, "EntryService", DummyEntryService)
    monkeypatch.setattr(
        agent_cli,
        "_load_policy",
        lambda **kwargs: {
            "version": 1,
            "default_effect": "allow",
            "rules": [],
            "output": {"safe_output_default": False},
            "secret_isolation": {"enabled": False},
        },
    )

    called = {}

    def fake_hydrate(pm, *, fingerprint, index, entry):
        called["fingerprint"] = fingerprint
        called["index"] = index
        called["partition"] = entry.get("partition")
        return {"kind": EntryType.SSH.value, "label": "SSHKey", "hydrated": True}

    monkeypatch.setattr(agent_cli, "_hydrate_partition_entry_if_needed", fake_hydrate)
    monkeypatch.setattr(
        agent_cli,
        "_resolve_secret_for_kind",
        lambda pm, service, entry, index: (
            "SSH_PRIVATE" if entry.get("hydrated") else ""
        ),
    )

    result = runner.invoke(
        app,
        [
            "--fingerprint",
            "ABC123",
            "agent",
            "lease-consume",
            "--reveal",
            "--",
            "lease-1",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["secret"] == "SSH_PRIVATE"
    assert called == {"fingerprint": "ABC123", "index": 7, "partition": "high_risk"}


def test_agent_high_risk_partition_migrate_command(monkeypatch, tmp_path):
    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    monkeypatch.setenv("SEEDPASS_PASSWORD", "pw")
    monkeypatch.setenv("SEEDPASS_HIGH_RISK_FACTOR", "factor-123")
    monkeypatch.setattr(agent_cli, "verify_high_risk_factor", lambda factor: True)
    monkeypatch.setattr(
        agent_cli, "partition_key_tag_for_factor", lambda factor: "partition-tag"
    )

    monkeypatch.setattr(
        agent_cli,
        "_load_policy",
        lambda **kwargs: {
            "secret_isolation": {"enabled": True, "high_risk_kinds": ["ssh", "seed"]}
        },
    )
    monkeypatch.setattr(
        agent_cli,
        "PasswordManager",
        lambda fingerprint, password: SimpleNamespace(
            fingerprint=fingerprint,
            password=password,
            fingerprint_dir=str(tmp_path / "fp"),
            vault=object(),
        ),
    )

    captured = {}

    def fake_migrate(
        *, vault, fingerprint_dir, partition_key_tag, high_risk_kinds
    ) -> dict:
        captured["partition_key_tag"] = partition_key_tag
        captured["high_risk_kinds"] = set(high_risk_kinds)
        captured["fingerprint_dir"] = str(fingerprint_dir)
        return {
            "moved_count": 2,
            "moved_indexes": ["1", "4"],
            "partition_file": str(
                Path(fingerprint_dir) / "seedpass_high_risk_entries.json.enc"
            ),
        }

    monkeypatch.setattr(agent_cli, "migrate_high_risk_entries", fake_migrate)

    result = runner.invoke(
        app,
        [
            "--fingerprint",
            "ABC123",
            "agent",
            "high-risk-partition-migrate",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["moved_count"] == 2
    assert captured["partition_key_tag"] == "partition-tag"
    assert captured["high_risk_kinds"] == {"ssh", "seed"}


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


def test_agent_posture_check_flags_policy_gate_and_rule_issues(monkeypatch, tmp_path):
    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    monkeypatch.setattr(agent_cli, "high_risk_factor_configured", lambda: True)
    policy = {
        "version": 1,
        "default_effect": "deny",
        "rules": [
            {
                "id": "allow_all_read",
                "effect": "allow",
                "operations": ["read"],
                "kinds": list(agent_cli.ALL_ENTRY_TYPES),
                "label_regex": ".*",
                "path_regex": "^entry/.*$",
                "fields": ["secret"],
            }
        ],
        "approvals": {"require_for": ["export"]},
        "secret_isolation": {
            "enabled": True,
            "high_risk_kinds": ["ssh", "seed"],
            "unlock_ttl_sec": 7200,
        },
        "output": {"safe_output_default": True, "redact_fields": ["secret"]},
    }
    (tmp_path / "agent_policy.json").write_text(json.dumps(policy), encoding="utf-8")
    result = runner.invoke(app, ["agent", "posture-check", "--fail-on", "high"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    ids = {f["id"] for f in payload["findings"]}
    assert "approvals_missing_required_actions" in ids
    assert "high_risk_unlock_ttl_too_long" in ids
    assert "over_permissive_read_rule" in ids
    assert "private_read_without_approval_gate" in ids


def test_agent_posture_check_flags_token_rotation_overdue(monkeypatch, tmp_path):
    import seedpass.core.agent_identity as identity_core

    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    monkeypatch.setattr(identity_core, "APP_DIR", tmp_path)

    identity_core.create_identity(
        identity_id="ci-bot",
        owner="secops",
        policy_binding="default",
        rotation_days=1,
    )
    stale_created = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
    stale_expires = (datetime.now(timezone.utc) + timedelta(days=3)).isoformat()
    agent_cli._save_token_store(
        {
            "version": agent_cli.TOKEN_STORE_VERSION,
            "tokens": [
                {
                    "id": "tok-1",
                    "name": "stale",
                    "token_hash": "x" * 64,
                    "created_at_utc": stale_created,
                    "expires_at_utc": stale_expires,
                    "revoked_at_utc": None,
                    "scopes": ["read"],
                    "kinds": ["password"],
                    "label_regex": ".*",
                    "uses_remaining": 5,
                    "identity_id": "ci-bot",
                }
            ],
        }
    )

    result = runner.invoke(app, ["agent", "posture-check", "--fail-on", "medium"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    ids = {f["id"] for f in payload["findings"]}
    assert "token_rotation_overdue" in ids


def test_agent_posture_check_runtime_requires_fingerprint(monkeypatch, tmp_path):
    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    result = runner.invoke(app, ["agent", "posture-check", "--check-runtime-config"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["reason"] == "missing_fingerprint_for_runtime_check"


def test_agent_posture_check_runtime_config_findings(monkeypatch, tmp_path):
    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    monkeypatch.setenv("SEEDPASS_PASSWORD", "pw")

    class DummyConfig:
        def get_quick_unlock(self):
            return True

        def get_kdf_mode(self):
            return "pbkdf2"

        def get_kdf_iterations(self):
            return 50_000

        def get_secret_class_partitions(self):
            return {
                "high_risk": {
                    "separate_factor_required": True,
                    "unlocked": True,
                }
            }

    monkeypatch.setattr(
        agent_cli,
        "PasswordManager",
        lambda fingerprint, password: SimpleNamespace(config_manager=DummyConfig()),
    )
    result = runner.invoke(
        app,
        [
            "--fingerprint",
            "ABC123",
            "agent",
            "posture-check",
            "--check-runtime-config",
            "--fail-on",
            "high",
        ],
    )
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["runtime_config_status"] == "checked"
    ids = {f["id"] for f in payload["findings"]}
    assert "quick_unlock_enabled" in ids
    assert "weak_kdf_iterations" in ids
    assert "high_risk_partition_persistently_unlocked" in ids


def test_agent_posture_remediate_emits_actions(monkeypatch, tmp_path):
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
    result = runner.invoke(app, ["agent", "posture-remediate", "--fail-on", "high"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["check"] == "agent_posture_remediation"
    assert payload["blocked"] is True
    action_ids = {a["finding_id"] for a in payload["actions"]}
    assert "policy_default_allow" in action_ids
    assert "safe_output_disabled" in action_ids
    assert "export_import_allowed" in action_ids


def test_agent_posture_remediate_runtime_requires_fingerprint(monkeypatch, tmp_path):
    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    result = runner.invoke(
        app, ["agent", "posture-remediate", "--check-runtime-config"]
    )
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["reason"] == "missing_fingerprint_for_runtime_check"


def test_agent_export_check_full_denied_by_default(monkeypatch, tmp_path):
    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    result = runner.invoke(app, ["agent", "export-check", "--mode", "full"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["allowed"] is False
    assert payload["reason"] == "policy_deny:full_export_blocked"


def test_agent_export_check_kind_allowed_default(monkeypatch, tmp_path):
    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    result = runner.invoke(
        app, ["agent", "export-check", "--mode", "kind", "--kind", "totp"]
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["allowed"] is True
    assert payload["reason"] == "policy_allow:kind_allowed"


def test_agent_export_check_strict_exit(monkeypatch, tmp_path):
    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    result = runner.invoke(
        app, ["agent", "export-check", "--mode", "full", "--strict-exit"]
    )
    assert result.exit_code == 1


def test_agent_export_manifest_verify_ok(monkeypatch, tmp_path):
    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    import seedpass.core.agent_export_policy as export_policy

    monkeypatch.setattr(export_policy, "APP_DIR", tmp_path)
    from seedpass.core.agent_export_policy import build_policy_filtered_export_package

    policy = agent_cli._load_policy(strict=False)
    package = build_policy_filtered_export_package(
        {
            "schema_version": 4,
            "entries": {
                "0": {"kind": "password", "label": "ok"},
                "1": {"kind": "totp", "label": "ok2"},
            },
        },
        policy,
    )
    export_file = tmp_path / "filtered.json"
    export_file.write_text(json.dumps(package), encoding="utf-8")

    result = runner.invoke(
        app, ["agent", "export-manifest-verify", "--file", str(export_file)]
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["valid"] is True
    assert payload["errors"] == []


def test_agent_export_manifest_verify_detects_policy_mismatch(monkeypatch, tmp_path):
    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    import seedpass.core.agent_export_policy as export_policy

    monkeypatch.setattr(export_policy, "APP_DIR", tmp_path)
    from seedpass.core.agent_export_policy import build_policy_filtered_export_package

    package = build_policy_filtered_export_package(
        {"schema_version": 4, "entries": {"0": {"kind": "password", "label": "ok"}}},
        agent_cli._load_policy(strict=False),
    )
    export_file = tmp_path / "filtered.json"
    export_file.write_text(json.dumps(package), encoding="utf-8")

    # Change policy after package creation to force policy stamp mismatch.
    (tmp_path / "agent_policy.json").write_text(
        json.dumps({"allow_kinds": ["totp"], "allow_export_import": False}),
        encoding="utf-8",
    )
    result = runner.invoke(
        app, ["agent", "export-manifest-verify", "--file", str(export_file)]
    )
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["valid"] is False
    assert "policy_stamp_mismatch" in payload["errors"]


def test_agent_export_manifest_verify_detects_tampered_entries(monkeypatch, tmp_path):
    monkeypatch.setattr(agent_cli, "APP_DIR", tmp_path)
    import seedpass.core.agent_export_policy as export_policy

    monkeypatch.setattr(export_policy, "APP_DIR", tmp_path)
    from seedpass.core.agent_export_policy import build_policy_filtered_export_package

    package = build_policy_filtered_export_package(
        {"schema_version": 4, "entries": {"0": {"kind": "password", "label": "ok"}}},
        agent_cli._load_policy(strict=False),
    )
    # Tamper entry kind to disallowed kind and keep original manifest.
    package["entries"]["0"]["kind"] = "ssh"
    export_file = tmp_path / "tampered.json"
    export_file.write_text(json.dumps(package), encoding="utf-8")

    result = runner.invoke(
        app, ["agent", "export-manifest-verify", "--file", str(export_file)]
    )
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["valid"] is False
    assert "entry_kind_not_allowed" in payload["errors"]
    assert "entries_hash_mismatch" in payload["errors"]
