from types import SimpleNamespace
from pathlib import Path
import os
import base64
import json
import pytest

from seedpass import api
import seedpass.core.agent_export_policy as export_policy
import seedpass.core.agent_approval as approval_core
import seedpass.core.agent_secret_isolation as isolation_core
import seedpass.core.agent_secret_lease as lease_core
import seedpass.core.agent_job as job_core
import seedpass.core.agent_recovery as recovery_core
import string
from seedpass.core.entry_types import EntryType
from seedpass.core.password_generation import PasswordGenerator, PasswordPolicy
from seedpass.core.encryption import EncryptionManager
from nostr.client import NostrClient, DEFAULT_RELAYS


@pytest.mark.anyio
async def test_create_and_modify_totp_entry(client):
    cl, token = client
    calls = {}

    def add_totp(label, seed, **kwargs):
        calls["create"] = kwargs
        return "uri"

    def modify(idx, **kwargs):
        calls["modify"] = (idx, kwargs)

    api.app.state.pm.entry_manager.add_totp = add_totp
    api.app.state.pm.entry_manager.modify_entry = modify
    api.app.state.pm.entry_manager.get_next_index = lambda: 5
    api.app.state.pm.parent_seed = "seed"

    headers = {"Authorization": f"Bearer {token}"}
    res = await cl.post(
        "/api/v1/entry",
        json={
            "type": "totp",
            "label": "T",
            "index": 1,
            "secret": "abc",
            "period": 60,
            "digits": 8,
            "notes": "n",
        },
        headers=headers,
    )
    assert res.status_code == 200
    assert res.json() == {"id": 5, "uri": "uri"}
    assert calls["create"] == {
        "index": 1,
        "secret": "abc",
        "period": 60,
        "digits": 8,
        "notes": "n",
        "archived": False,
        "deterministic": False,
    }

    res = await cl.put(
        "/api/v1/entry/5",
        json={"period": 90, "digits": 6},
        headers=headers,
    )
    assert res.status_code == 200
    assert calls["modify"][0] == 5
    assert calls["modify"][1]["period"] == 90
    assert calls["modify"][1]["digits"] == 6


@pytest.mark.anyio
async def test_create_and_modify_ssh_entry(client):
    cl, token = client
    calls = {}

    def add_ssh(label, seed, **kwargs):
        calls["create"] = kwargs
        return 2

    def modify(idx, **kwargs):
        calls["modify"] = (idx, kwargs)

    api.app.state.pm.entry_manager.add_ssh_key = add_ssh
    api.app.state.pm.entry_manager.modify_entry = modify
    api.app.state.pm.parent_seed = "seed"

    headers = {"Authorization": f"Bearer {token}"}
    res = await cl.post(
        "/api/v1/entry",
        json={"type": "ssh", "label": "S", "index": 2, "notes": "n"},
        headers=headers,
    )
    assert res.status_code == 200
    assert res.json() == {"id": 2}
    assert calls["create"] == {"index": 2, "notes": "n", "archived": False}

    res = await cl.put(
        "/api/v1/entry/2",
        json={"notes": "x"},
        headers=headers,
    )
    assert res.status_code == 200
    assert calls["modify"][0] == 2
    assert calls["modify"][1]["notes"] == "x"


@pytest.mark.anyio
async def test_create_and_modify_document_entry(client):
    cl, token = client
    calls = {}

    def add_document(label, content, **kwargs):
        calls["create"] = (label, content, kwargs)
        return 11

    def modify(idx, **kwargs):
        calls["modify"] = (idx, kwargs)

    api.app.state.pm.entry_manager.add_document = add_document
    api.app.state.pm.entry_manager.modify_entry = modify

    headers = {"Authorization": f"Bearer {token}"}
    res = await cl.post(
        "/api/v1/entry",
        json={
            "type": "document",
            "title": "Runbook",
            "content": "line1\\nline2",
            "file_type": "md",
            "notes": "ops",
            "tags": ["doc", "ops"],
        },
        headers=headers,
    )
    assert res.status_code == 200
    assert res.json() == {"id": 11}
    assert calls["create"] == (
        "Runbook",
        "line1\\nline2",
        {"file_type": "md", "notes": "ops", "archived": False, "tags": ["doc", "ops"]},
    )

    res = await cl.put(
        "/api/v1/entry/11",
        json={"content": "line1\\nline2\\nline3", "file_type": "txt"},
        headers=headers,
    )
    assert res.status_code == 200
    assert calls["modify"][0] == 11
    assert calls["modify"][1]["content"].endswith("line3")
    assert calls["modify"][1]["file_type"] == "txt"


@pytest.mark.anyio
async def test_document_import_export_endpoints(client):
    cl, token = client
    calls = {}

    def import_document(path, **kwargs):
        calls["import"] = (path, kwargs)
        return 33

    def export_document(idx, **kwargs):
        calls["export"] = (idx, kwargs)
        return Path("/tmp/exported.md")

    api.app.state.pm.entry_manager.import_document_file = import_document
    api.app.state.pm.entry_manager.export_document_file = export_document

    headers = {"Authorization": f"Bearer {token}"}
    imported = await cl.post(
        "/api/v1/entry/document/import",
        json={"path": "/tmp/source.md", "label": "Imported", "notes": "n"},
        headers=headers,
    )
    assert imported.status_code == 200
    assert imported.json() == {"id": 33}
    assert calls["import"] == (
        "/tmp/source.md",
        {"label": "Imported", "notes": "n", "archived": False, "tags": None},
    )

    exported = await cl.post(
        "/api/v1/entry/33/document/export",
        json={"path": "/tmp/out", "overwrite": True},
        headers=headers,
    )
    assert exported.status_code == 200
    assert exported.json() == {"path": "/tmp/exported.md"}
    assert calls["export"] == (33, {"output_path": "/tmp/out", "overwrite": True})


@pytest.mark.anyio
async def test_entry_links_endpoints(client):
    cl, token = client
    calls = {}

    def add_link(entry_id, target_id, **kwargs):
        calls["add"] = (entry_id, target_id, kwargs)
        return [
            {
                "target_id": target_id,
                "relation": kwargs["relation"],
                "note": kwargs["note"],
            }
        ]

    def remove_link(entry_id, target_id, **kwargs):
        calls["remove"] = (entry_id, target_id, kwargs)
        return []

    def get_links(entry_id):
        calls["get"] = entry_id
        return [
            {
                "target_id": 2,
                "relation": "references",
                "note": "used by doc",
                "target_label": "API Token",
                "target_kind": "key_value",
            }
        ]

    api.app.state.pm.entry_manager.add_link = add_link
    api.app.state.pm.entry_manager.remove_link = remove_link
    api.app.state.pm.entry_manager.get_links = get_links

    headers = {"Authorization": f"Bearer {token}"}
    created = await cl.post(
        "/api/v1/entry/1/links",
        json={"target_id": 2, "relation": "references", "note": "used by doc"},
        headers=headers,
    )
    assert created.status_code == 200
    assert created.json()["links"][0]["target_id"] == 2
    assert calls["add"] == (1, 2, {"relation": "references", "note": "used by doc"})

    listed = await cl.get("/api/v1/entry/1/links", headers=headers)
    assert listed.status_code == 200
    assert listed.json()["entry_id"] == 1
    assert listed.json()["links"][0]["target_kind"] == "key_value"
    assert calls["get"] == 1

    removed = await cl.request(
        "DELETE",
        "/api/v1/entry/1/links",
        json={"target_id": 2, "relation": "references"},
        headers=headers,
    )
    assert removed.status_code == 200
    assert removed.json() == {"entry_id": 1, "links": []}
    assert calls["remove"] == (1, 2, {"relation": "references"})


@pytest.mark.anyio
async def test_update_entry_error(client):
    cl, token = client

    def modify(*a, **k):
        raise ValueError("nope")

    api.app.state.pm.entry_manager.modify_entry = modify
    headers = {"Authorization": f"Bearer {token}"}
    res = await cl.put("/api/v1/entry/1", json={"username": "x"}, headers=headers)
    assert res.status_code == 400
    assert res.json() == {"detail": "nope"}


@pytest.mark.anyio
async def test_get_entry_private_kind_blocked_when_high_risk_locked(
    client, tmp_path, monkeypatch
):
    cl, token = client
    monkeypatch.setattr(export_policy, "APP_DIR", tmp_path)
    monkeypatch.setattr(isolation_core, "APP_DIR", tmp_path)
    isolation_core.set_high_risk_factor("factor-get")
    (tmp_path / "agent_policy.json").write_text(
        json.dumps({"secret_isolation": {"enabled": True, "high_risk_kinds": ["ssh"]}}),
        encoding="utf-8",
    )
    api.app.state.pm.current_fingerprint = "ABC123"
    api.app.state.pm.entry_manager.retrieve_entry = lambda _i: {
        "kind": "ssh",
        "label": "SSH key",
    }

    headers = {
        "Authorization": f"Bearer {token}",
        "X-SeedPass-Password": "pw",
    }
    blocked = await cl.get("/api/v1/entry/1", headers=headers)
    assert blocked.status_code == 403
    assert blocked.json()["detail"] == "policy_deny:high_risk_locked"

    unlock_headers = {
        "Authorization": f"Bearer {token}",
        "X-SeedPass-Password": "pw",
        "X-SeedPass-High-Risk-Factor": "factor-get",
    }
    unlocked = await cl.post(
        "/api/v1/high-risk/unlock", json={"ttl": 120}, headers=unlock_headers
    )
    assert unlocked.status_code == 200

    allowed = await cl.get("/api/v1/entry/1", headers=headers)
    assert allowed.status_code == 200
    assert allowed.json()["kind"] == "ssh"


@pytest.mark.anyio
async def test_get_entry_hydrates_partitioned_high_risk_entry(client, monkeypatch):
    cl, token = client
    api.app.state.pm.current_fingerprint = "ABC123"
    api.app.state.pm.fingerprint_dir = "/tmp/seedpass-tests/fp"
    api.app.state.pm.entry_manager.retrieve_entry = lambda _i: {
        "kind": "ssh",
        "label": "SSH key",
        "partition": "high_risk",
    }
    monkeypatch.setattr(api, "high_risk_factor_configured", lambda: False)
    monkeypatch.setattr(api, "unlocked_partition_key_tag", lambda **kwargs: "tag-123")
    monkeypatch.setattr(
        api,
        "load_partition_entry",
        lambda fingerprint_dir, partition_key_tag, index: {
            "kind": "ssh",
            "label": "SSH key",
            "notes": "from-partition",
        },
    )

    headers = {
        "Authorization": f"Bearer {token}",
        "X-SeedPass-Password": "pw",
    }
    res = await cl.get("/api/v1/entry/1", headers=headers)
    assert res.status_code == 200
    payload = res.json()
    assert payload["kind"] == "ssh"
    assert payload["notes"] == "from-partition"


@pytest.mark.anyio
async def test_update_config_secret_mode(client):
    cl, token = client
    called = {}

    def set_secret(val):
        called["val"] = val

    api.app.state.pm.config_manager.set_secret_mode_enabled = set_secret
    headers = {"Authorization": f"Bearer {token}"}
    res = await cl.put(
        "/api/v1/config/secret_mode_enabled",
        json={"value": True},
        headers=headers,
    )
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}
    assert called["val"] is True


@pytest.mark.anyio
async def test_totp_export_endpoint(client):
    cl, token = client
    api.app.state.pm.entry_manager.export_totp_entries = lambda seed: {"entries": ["x"]}
    api.app.state.pm.parent_seed = "seed"
    headers = {"Authorization": f"Bearer {token}", "X-SeedPass-Password": "pw"}
    res = await cl.get("/api/v1/totp/export", headers=headers)
    assert res.status_code == 200
    assert res.json() == {"entries": ["x"]}


@pytest.mark.anyio
async def test_totp_codes_endpoint(client):
    cl, token = client
    api.app.state.pm.entry_manager.list_entries = lambda **kw: [
        (0, "Email", None, None, False)
    ]
    api.app.state.pm.entry_manager.get_totp_code = lambda i, s: "123456"
    api.app.state.pm.entry_manager.get_totp_time_remaining = lambda i: 30
    api.app.state.pm.parent_seed = "seed"
    headers = {"Authorization": f"Bearer {token}", "X-SeedPass-Password": "pw"}
    res = await cl.get("/api/v1/totp", headers=headers)
    assert res.status_code == 200
    assert res.json() == {
        "codes": [
            {"id": 0, "label": "Email", "code": "123456", "seconds_remaining": 30}
        ]
    }


@pytest.mark.anyio
async def test_parent_seed_endpoint_removed(client):
    cl, token = client
    res = await cl.get(
        "/api/v1/parent-seed", headers={"Authorization": f"Bearer {token}"}
    )
    assert res.status_code == 404


@pytest.mark.anyio
async def test_fingerprint_endpoints(client):
    cl, token = client
    calls = {}

    api.app.state.pm.add_new_fingerprint = lambda: calls.setdefault("add", True)
    api.app.state.pm.fingerprint_manager.remove_fingerprint = (
        lambda fp: calls.setdefault("remove", fp)
    )
    api.app.state.pm.select_fingerprint = lambda fp: calls.setdefault("select", fp)

    headers = {"Authorization": f"Bearer {token}"}

    res = await cl.post("/api/v1/fingerprint", headers=headers)
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}
    assert calls.get("add") is True

    res = await cl.delete("/api/v1/fingerprint/abc", headers=headers)
    assert res.status_code == 200
    assert res.json() == {"status": "deleted"}
    assert calls.get("remove") == "abc"

    res = await cl.post(
        "/api/v1/fingerprint/select",
        json={"fingerprint": "xyz"},
        headers=headers,
    )
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}
    assert calls.get("select") == "xyz"


@pytest.mark.anyio
async def test_checksum_endpoints(client):
    cl, token = client
    calls = {}

    api.app.state.pm.handle_verify_checksum = lambda: calls.setdefault("verify", True)
    api.app.state.pm.handle_update_script_checksum = lambda: calls.setdefault(
        "update", True
    )

    headers = {"Authorization": f"Bearer {token}"}

    res = await cl.post("/api/v1/checksum/verify", headers=headers)
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}
    assert calls.get("verify") is True

    res = await cl.post("/api/v1/checksum/update", headers=headers)
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}
    assert calls.get("update") is True


@pytest.mark.anyio
async def test_vault_import_via_path(client, tmp_path):
    cl, token = client
    called = {}

    def import_db(path):
        called["path"] = path

    api.app.state.pm.handle_import_database = import_db
    api.app.state.pm.sync_vault = lambda: called.setdefault("sync", True)
    api.app.state.pm.encryption_manager = SimpleNamespace(
        resolve_relative_path=lambda p: p
    )
    file_path = tmp_path / "b.json.enc"
    file_path.write_text("{}")

    headers = {"Authorization": f"Bearer {token}"}
    res = await cl.post(
        "/api/v1/vault/import",
        json={"path": str(file_path)},
        headers=headers,
    )
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}
    assert called["path"] == file_path
    assert called.get("sync") is True


@pytest.mark.anyio
async def test_vault_import_via_upload(client, tmp_path):
    cl, token = client
    called = {}

    def import_db(path):
        called["path"] = path

    api.app.state.pm.handle_import_database = import_db
    api.app.state.pm.sync_vault = lambda: called.setdefault("sync", True)
    file_path = tmp_path / "c.json"
    file_path.write_text("{}")

    headers = {"Authorization": f"Bearer {token}"}
    with open(file_path, "rb") as fh:
        res = await cl.post(
            "/api/v1/vault/import",
            files={"file": ("c.json", fh.read())},
            headers=headers,
        )
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}
    assert isinstance(called.get("path"), Path)
    assert called.get("sync") is True


@pytest.mark.anyio
async def test_vault_import_upload_sets_secure_temp_permissions(client, monkeypatch):
    cl, token = client
    called = {}
    chmod_calls = []
    unlink_calls = []

    def import_db(path):
        called["path"] = path

    api.app.state.pm.handle_import_database = import_db
    api.app.state.pm.sync_vault = lambda: called.setdefault("sync", True)

    real_chmod = api.os.chmod
    real_unlink = api.os.unlink

    def tracking_chmod(path, mode):
        chmod_calls.append((Path(path), mode))
        return real_chmod(path, mode)

    def tracking_unlink(path):
        unlink_calls.append(Path(path))
        return real_unlink(path)

    monkeypatch.setattr(api.os, "chmod", tracking_chmod)
    monkeypatch.setattr(api.os, "unlink", tracking_unlink)

    headers = {"Authorization": f"Bearer {token}"}
    res = await cl.post(
        "/api/v1/vault/import",
        files={"file": ("c.json.enc", b"{}")},
        headers=headers,
    )
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}
    tmp_path_used = called["path"]
    assert any(path == tmp_path_used and mode == 0o600 for path, mode in chmod_calls)
    assert tmp_path_used in unlink_calls


@pytest.mark.anyio
async def test_vault_import_upload_temp_file_removed_on_failure(client, monkeypatch):
    cl, token = client
    called = {}
    unlink_calls = []

    def import_db(path):
        called["path"] = path
        raise ValueError("boom")

    api.app.state.pm.handle_import_database = import_db
    api.app.state.pm.sync_vault = lambda: called.setdefault("sync", True)

    real_unlink = api.os.unlink

    def tracking_unlink(path):
        unlink_calls.append(Path(path))
        return real_unlink(path)

    monkeypatch.setattr(api.os, "unlink", tracking_unlink)

    headers = {"Authorization": f"Bearer {token}"}
    with pytest.raises(ValueError):
        await cl.post(
            "/api/v1/vault/import",
            files={"file": ("c.json.enc", b"{}")},
            headers=headers,
        )
    assert called["path"] in unlink_calls
    assert not called.get("sync", False)


@pytest.mark.anyio
async def test_vault_import_upload_too_large(client):
    cl, token = client
    called = {}
    api.app.state.pm.handle_import_database = lambda path: called.setdefault(
        "import_called", True
    )
    api.app.state.pm.sync_vault = lambda: called.setdefault("sync_called", True)

    old_limit = api._MAX_IMPORT_BYTES
    api._MAX_IMPORT_BYTES = 8
    try:
        headers = {"Authorization": f"Bearer {token}"}
        res = await cl.post(
            "/api/v1/vault/import",
            files={"file": ("big.json.enc", b"123456789")},
            headers=headers,
        )
    finally:
        api._MAX_IMPORT_BYTES = old_limit

    assert res.status_code == 413
    assert "exceeds max size" in res.json()["detail"]
    assert called == {}


@pytest.mark.anyio
async def test_vault_import_invalid_extension(client):
    cl, token = client
    api.app.state.pm.handle_import_database = lambda path: None
    api.app.state.pm.sync_vault = lambda: None
    api.app.state.pm.encryption_manager = SimpleNamespace(
        resolve_relative_path=lambda p: p
    )

    headers = {"Authorization": f"Bearer {token}"}
    res = await cl.post(
        "/api/v1/vault/import",
        json={"path": "bad.txt"},
        headers=headers,
    )
    assert res.status_code == 400


@pytest.mark.anyio
async def test_vault_import_path_traversal_blocked(client, tmp_path):
    cl, token = client
    key = base64.urlsafe_b64encode(os.urandom(32))
    api.app.state.pm.encryption_manager = EncryptionManager(key, tmp_path)
    api.app.state.pm.handle_import_database = lambda path: None
    api.app.state.pm.sync_vault = lambda: None

    headers = {"Authorization": f"Bearer {token}"}
    res = await cl.post(
        "/api/v1/vault/import",
        json={"path": "../evil.json.enc"},
        headers=headers,
    )
    assert res.status_code == 400


@pytest.mark.anyio
async def test_vault_lock_endpoint(client):
    cl, token = client
    called = {}

    def lock():
        called["locked"] = True
        api.app.state.pm.locked = True

    api.app.state.pm.lock_vault = lock
    api.app.state.pm.locked = False

    headers = {"Authorization": f"Bearer {token}"}
    res = await cl.post("/api/v1/vault/lock", headers=headers)
    assert res.status_code == 200
    assert res.json() == {"status": "locked"}
    assert called.get("locked") is True
    assert api.app.state.pm.locked is True
    api.app.state.pm.unlock_vault = lambda pw: setattr(
        api.app.state.pm, "locked", False
    )
    api.app.state.pm.unlock_vault("pw")
    assert api.app.state.pm.locked is False


@pytest.mark.anyio
async def test_vault_unlock_endpoint(client):
    cl, token = client
    called = {}

    def unlock(pw):
        called["password"] = pw
        api.app.state.pm.locked = False
        api.app.state.pm.is_locked = False
        return 0.123

    api.app.state.pm.verify_password = lambda pw: pw == "pw"
    api.app.state.pm.unlock_vault = unlock
    api.app.state.pm.locked = True
    api.app.state.pm.is_locked = True

    headers = {"Authorization": f"Bearer {token}", "X-SeedPass-Password": "pw"}
    res = await cl.post("/api/v1/vault/unlock", headers=headers)
    assert res.status_code == 200
    assert res.json()["status"] == "unlocked"
    assert "help_hint" in res.json()
    assert called["password"] == "pw"


@pytest.mark.anyio
async def test_vault_unlock_rate_limited_after_failed_attempts(client, monkeypatch):
    cl, token = client
    api.app.state.pm.verify_password = lambda _pw: False
    api.app.state.pm.unlock_vault = lambda _pw: 0.01

    monkeypatch.setattr(api, "_UNLOCK_ATTEMPT_LIMIT", 2)
    monkeypatch.setattr(api, "_UNLOCK_ATTEMPT_WINDOW", 600)

    headers = {"Authorization": f"Bearer {token}", "X-SeedPass-Password": "bad"}
    res1 = await cl.post("/api/v1/vault/unlock", headers=headers)
    assert res1.status_code == 401
    res2 = await cl.post("/api/v1/vault/unlock", headers=headers)
    assert res2.status_code == 401
    res3 = await cl.post("/api/v1/vault/unlock", headers=headers)
    assert res3.status_code == 429


@pytest.mark.anyio
async def test_entry_endpoints_blocked_when_vault_locked(client):
    cl, token = client
    api.app.state.pm.locked = True
    api.app.state.pm.is_locked = True

    headers = {"Authorization": f"Bearer {token}"}
    res = await cl.get("/api/v1/entry", params={"query": "x"}, headers=headers)
    assert res.status_code == 423
    assert res.json()["detail"] == "Vault is locked"


@pytest.mark.anyio
async def test_generate_password_blocked_when_vault_locked(client):
    cl, token = client
    api.app.state.pm.locked = True
    api.app.state.pm.is_locked = True

    headers = {"Authorization": f"Bearer {token}"}
    res = await cl.post("/api/v1/password", headers=headers, json={"length": 12})
    assert res.status_code == 423
    assert res.json()["detail"] == "Vault is locked"


@pytest.mark.anyio
async def test_config_endpoint_blocked_when_vault_locked(client):
    cl, token = client
    api.app.state.pm.locked = True
    api.app.state.pm.is_locked = True

    headers = {"Authorization": f"Bearer {token}"}
    res = await cl.get("/api/v1/config/k", headers=headers)
    assert res.status_code == 423
    assert res.json()["detail"] == "Vault is locked"


@pytest.mark.anyio
async def test_get_config_denies_sensitive_keys(client):
    cl, token = client
    api.app.state.pm.locked = False
    api.app.state.pm.is_locked = False
    headers = {"Authorization": f"Bearer {token}"}
    res = await cl.get("/api/v1/config/password_hash", headers=headers)
    assert res.status_code == 403


@pytest.mark.anyio
async def test_lock_unlock_cycle_restores_entry_access(client):
    cl, token = client
    api.app.state.pm.locked = False
    api.app.state.pm.is_locked = False
    api.app.state.pm.verify_password = lambda pw: pw == "pw"
    api.app.state.pm.lock_vault = lambda: (
        setattr(api.app.state.pm, "locked", True),
        setattr(api.app.state.pm, "is_locked", True),
    )
    api.app.state.pm.unlock_vault = lambda pw: (
        setattr(api.app.state.pm, "locked", False),
        setattr(api.app.state.pm, "is_locked", False),
        0.01,
    )[-1]

    auth = {"Authorization": f"Bearer {token}"}
    locked_res = await cl.post("/api/v1/vault/lock", headers=auth)
    assert locked_res.status_code == 200

    denied = await cl.get("/api/v1/entry", params={"query": "x"}, headers=auth)
    assert denied.status_code == 423

    unlocked = await cl.post(
        "/api/v1/vault/unlock",
        headers={**auth, "X-SeedPass-Password": "pw"},
    )
    assert unlocked.status_code == 200

    allowed = await cl.get("/api/v1/entry", params={"query": "x"}, headers=auth)
    assert allowed.status_code == 200


@pytest.mark.anyio
async def test_secret_mode_endpoint(client):
    cl, token = client
    called = {}

    def set_secret(val):
        called.setdefault("enabled", val)

    def set_delay(val):
        called.setdefault("delay", val)

    api.app.state.pm.config_manager.set_secret_mode_enabled = set_secret
    api.app.state.pm.config_manager.set_clipboard_clear_delay = set_delay

    headers = {"Authorization": f"Bearer {token}"}
    res = await cl.post(
        "/api/v1/secret-mode",
        json={"enabled": True, "delay": 12},
        headers=headers,
    )
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}
    assert called["enabled"] is True
    assert called["delay"] == 12


@pytest.mark.anyio
async def test_vault_export_endpoint(client, tmp_path):
    cl, token = client
    out = tmp_path / "out.json"
    out.write_text("data")

    api.app.state.pm.handle_export_database = lambda *a, **k: out

    headers = {
        "Authorization": f"Bearer {token}",
        "X-SeedPass-Password": "pw",
    }
    res = await cl.post("/api/v1/vault/export", headers=headers)
    assert res.status_code == 200
    assert res.content == b"data"

    res = await cl.post(
        "/api/v1/vault/export", headers={"Authorization": f"Bearer {token}"}
    )
    assert res.status_code == 401


@pytest.mark.anyio
async def test_vault_export_endpoint_denied_for_agent_profile(
    client, tmp_path, monkeypatch
):
    cl, token = client
    called = {}
    monkeypatch.setattr(export_policy, "APP_DIR", tmp_path)
    monkeypatch.setattr(
        api,
        "record_export_policy_event",
        lambda event, details: called.setdefault("event", (event, details)),
    )
    headers = {
        "Authorization": f"Bearer {token}",
        "X-SeedPass-Password": "pw",
        "X-SeedPass-Agent-Profile": "true",
    }
    res = await cl.post("/api/v1/vault/export", headers=headers)
    assert res.status_code == 403
    assert res.json()["detail"] == "policy_deny:full_export_blocked"
    assert called["event"][0] == "export_denied"


@pytest.mark.anyio
async def test_vault_export_endpoint_policy_filtered_manifest(
    client, tmp_path, monkeypatch
):
    cl, token = client
    monkeypatch.setattr(export_policy, "APP_DIR", tmp_path)
    (tmp_path / "agent_policy.json").write_text(
        '{"allow_kinds":["password"],"allow_export_import":false}',
        encoding="utf-8",
    )
    api.app.state.pm.vault = SimpleNamespace(
        load_index=lambda: {
            "schema_version": 4,
            "entries": {
                "0": {"kind": "password", "label": "ok"},
                "1": {"kind": "totp", "label": "skip"},
            },
        },
        encryption_manager=SimpleNamespace(encrypt_data=lambda payload: payload),
    )
    headers = {
        "Authorization": f"Bearer {token}",
        "X-SeedPass-Password": "pw",
        "X-SeedPass-Agent-Profile": "true",
        "X-SeedPass-Policy-Filtered": "true",
    }
    res = await cl.post("/api/v1/vault/export", headers=headers)
    assert res.status_code == 200
    payload = json.loads(res.content.decode("utf-8"))
    assert payload["_export_manifest"]["mode"] == "policy_filtered"
    assert payload["_export_manifest"]["allow_kinds"] == ["password"]
    assert payload["_export_manifest"]["included_entry_indexes"] == ["0"]


@pytest.mark.anyio
async def test_vault_export_endpoint_requires_approval_when_configured(
    client, tmp_path, monkeypatch
):
    cl, token = client
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
    headers = {
        "Authorization": f"Bearer {token}",
        "X-SeedPass-Password": "pw",
        "X-SeedPass-Agent-Profile": "true",
    }
    res = await cl.post("/api/v1/vault/export", headers=headers)
    assert res.status_code == 403
    assert res.json()["detail"] == "policy_deny:approval_required"


@pytest.mark.anyio
async def test_vault_export_endpoint_blocked_when_high_risk_locked(
    client, tmp_path, monkeypatch
):
    cl, token = client
    monkeypatch.setattr(export_policy, "APP_DIR", tmp_path)
    monkeypatch.setattr(isolation_core, "APP_DIR", tmp_path)
    isolation_core.set_high_risk_factor("factor-abc")
    (tmp_path / "agent_policy.json").write_text(
        json.dumps(
            {
                "allow_export_import": True,
                "export": {"allow_full_vault": True},
                "approvals": {"require_for": []},
                "secret_isolation": {"enabled": True, "high_risk_kinds": ["seed"]},
            }
        ),
        encoding="utf-8",
    )
    headers = {
        "Authorization": f"Bearer {token}",
        "X-SeedPass-Password": "pw",
        "X-SeedPass-Agent-Profile": "true",
    }
    res = await cl.post("/api/v1/vault/export", headers=headers)
    assert res.status_code == 403
    assert res.json()["detail"] == "policy_deny:high_risk_locked"


@pytest.mark.anyio
async def test_vault_export_endpoint_approval_allows_full_export(
    client, tmp_path, monkeypatch
):
    cl, token = client
    out = tmp_path / "out.json"
    out.write_text("data")
    api.app.state.pm.handle_export_database = lambda *a, **k: out

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
    approval = approval_core.issue_approval(
        action="export",
        ttl_seconds=300,
        uses=1,
        resource="vault:full",
    )

    headers = {
        "Authorization": f"Bearer {token}",
        "X-SeedPass-Password": "pw",
        "X-SeedPass-Agent-Profile": "true",
        "X-SeedPass-Approval-Id": approval["id"],
    }
    res = await cl.post("/api/v1/vault/export", headers=headers)
    assert res.status_code == 200
    assert res.content == b"data"


@pytest.mark.anyio
async def test_totp_export_endpoint_denied_for_agent_profile(
    client, tmp_path, monkeypatch
):
    cl, token = client
    monkeypatch.setattr(export_policy, "APP_DIR", tmp_path)
    (tmp_path / "agent_policy.json").write_text(
        '{"allow_kinds":["password"],"allow_export_import":false}',
        encoding="utf-8",
    )
    headers = {
        "Authorization": f"Bearer {token}",
        "X-SeedPass-Password": "pw",
        "X-SeedPass-Agent-Profile": "true",
    }
    res = await cl.get("/api/v1/totp/export", headers=headers)
    assert res.status_code == 403
    assert res.json()["detail"] == "policy_deny:kind_not_allowed"


@pytest.mark.anyio
async def test_export_check_endpoint_full_denied_default(client, tmp_path, monkeypatch):
    cl, token = client
    monkeypatch.setattr(export_policy, "APP_DIR", tmp_path)
    headers = {"Authorization": f"Bearer {token}"}
    res = await cl.get("/api/v1/export/check", params={"mode": "full"}, headers=headers)
    assert res.status_code == 200
    payload = res.json()
    assert payload["status"] == "ok"
    assert payload["allowed"] is False
    assert payload["reason"] == "policy_deny:full_export_blocked"


@pytest.mark.anyio
async def test_export_check_endpoint_kind_allowed_default(
    client, tmp_path, monkeypatch
):
    cl, token = client
    monkeypatch.setattr(export_policy, "APP_DIR", tmp_path)
    headers = {"Authorization": f"Bearer {token}"}
    res = await cl.get(
        "/api/v1/export/check",
        params={"mode": "kind", "kind": "totp"},
        headers=headers,
    )
    assert res.status_code == 200
    payload = res.json()
    assert payload["status"] == "ok"
    assert payload["allowed"] is True
    assert payload["reason"] == "policy_allow:kind_allowed"


@pytest.mark.anyio
async def test_export_check_endpoint_kind_requires_kind(client):
    cl, token = client
    headers = {"Authorization": f"Bearer {token}"}
    res = await cl.get("/api/v1/export/check", params={"mode": "kind"}, headers=headers)
    assert res.status_code == 400
    assert res.json()["detail"] == "missing_kind"


@pytest.mark.anyio
async def test_export_manifest_verify_endpoint_ok(client, tmp_path, monkeypatch):
    cl, token = client
    monkeypatch.setattr(export_policy, "APP_DIR", tmp_path)
    policy = export_policy.load_export_policy()
    package = export_policy.build_policy_filtered_export_package(
        {"schema_version": 4, "entries": {"0": {"kind": "password", "label": "ok"}}},
        policy,
    )
    headers = {"Authorization": f"Bearer {token}"}
    res = await cl.post("/api/v1/export/manifest/verify", headers=headers, json=package)
    assert res.status_code == 200
    payload = res.json()
    assert payload["status"] == "ok"
    assert payload["valid"] is True
    assert payload["errors"] == []


@pytest.mark.anyio
async def test_export_manifest_verify_endpoint_mismatch(client, tmp_path, monkeypatch):
    cl, token = client
    monkeypatch.setattr(export_policy, "APP_DIR", tmp_path)
    package = export_policy.build_policy_filtered_export_package(
        {"schema_version": 4, "entries": {"0": {"kind": "password", "label": "ok"}}},
        export_policy.load_export_policy(),
    )
    # Change policy after package creation to force mismatch.
    (tmp_path / "agent_policy.json").write_text(
        '{"allow_kinds":["totp"],"allow_export_import":false}',
        encoding="utf-8",
    )
    headers = {"Authorization": f"Bearer {token}"}
    res = await cl.post("/api/v1/export/manifest/verify", headers=headers, json=package)
    assert res.status_code == 200
    payload = res.json()
    assert payload["status"] == "ok"
    assert payload["valid"] is False
    assert "policy_stamp_mismatch" in payload["errors"]


@pytest.mark.anyio
async def test_export_manifest_verify_endpoint_detects_tamper(
    client, tmp_path, monkeypatch
):
    cl, token = client
    monkeypatch.setattr(export_policy, "APP_DIR", tmp_path)
    policy = export_policy.load_export_policy()
    package = export_policy.build_policy_filtered_export_package(
        {"schema_version": 4, "entries": {"0": {"kind": "password", "label": "ok"}}},
        policy,
    )
    package["entries"]["0"]["kind"] = "ssh"
    headers = {"Authorization": f"Bearer {token}"}
    res = await cl.post("/api/v1/export/manifest/verify", headers=headers, json=package)
    assert res.status_code == 200
    payload = res.json()
    assert payload["status"] == "ok"
    assert payload["valid"] is False
    assert "entry_kind_not_allowed" in payload["errors"]
    assert "entries_hash_mismatch" in payload["errors"]


@pytest.mark.anyio
async def test_backup_parent_seed_endpoint(client, tmp_path):
    cl, token = client
    api.app.state.pm.parent_seed = "seed"
    called = {}
    api.app.state.pm.encryption_manager = SimpleNamespace(
        encrypt_and_save_file=lambda data, path: called.setdefault("path", path),
        resolve_relative_path=lambda p: p,
    )
    path = Path("seed.enc")
    headers = {
        "Authorization": f"Bearer {token}",
        "X-SeedPass-Password": "pw",
    }
    res = await cl.post(
        "/api/v1/vault/backup-parent-seed",
        json={"path": str(path), "confirm": True},
        headers=headers,
    )
    assert res.status_code == 200
    assert res.json() == {"status": "saved", "path": str(path)}
    assert called["path"] == path

    res = await cl.post(
        "/api/v1/vault/backup-parent-seed",
        json={"path": str(path)},
        headers=headers,
    )
    assert res.status_code == 400


@pytest.mark.anyio
async def test_high_risk_api_unlock_status_and_lock(client, tmp_path, monkeypatch):
    cl, token = client
    monkeypatch.setattr(export_policy, "APP_DIR", tmp_path)
    monkeypatch.setattr(isolation_core, "APP_DIR", tmp_path)
    isolation_core.set_high_risk_factor("factor-123")
    api.app.state.pm.current_fingerprint = "ABC123"

    headers = {"Authorization": f"Bearer {token}"}
    status_before = await cl.get("/api/v1/high-risk/status", headers=headers)
    assert status_before.status_code == 200
    before_payload = status_before.json()
    assert before_payload["status"] == "ok"
    assert before_payload["unlocked"] is False

    unlock_headers = {
        "Authorization": f"Bearer {token}",
        "X-SeedPass-Password": "pw",
        "X-SeedPass-High-Risk-Factor": "factor-123",
    }
    unlocked = await cl.post(
        "/api/v1/high-risk/unlock",
        json={"ttl": 120},
        headers=unlock_headers,
    )
    assert unlocked.status_code == 200
    unlocked_payload = unlocked.json()
    assert unlocked_payload["status"] == "ok"
    assert unlocked_payload["fingerprint"] == "ABC123"

    status_after = await cl.get("/api/v1/high-risk/status", headers=headers)
    assert status_after.status_code == 200
    assert status_after.json()["unlocked"] is True

    locked = await cl.post("/api/v1/high-risk/lock", headers=headers)
    assert locked.status_code == 200
    assert locked.json()["status"] == "ok"

    status_final = await cl.get("/api/v1/high-risk/status", headers=headers)
    assert status_final.status_code == 200
    assert status_final.json()["unlocked"] is False


@pytest.mark.anyio
async def test_agent_job_profiles_crud_endpoints(client, tmp_path, monkeypatch):
    cl, token = client
    monkeypatch.setattr(job_core, "APP_DIR", tmp_path)
    api.app.state.pm.current_fingerprint = "ABC123"
    headers = {"Authorization": f"Bearer {token}"}

    created = await cl.post(
        "/api/v1/agent/job-profiles",
        headers=headers,
        json={"id": "nightly", "query": "Site", "auth_broker": "keyring"},
    )
    assert created.status_code == 200
    created_payload = created.json()
    assert created_payload["status"] == "ok"
    assert created_payload["job_profile"]["id"] == "nightly"

    listed = await cl.get("/api/v1/agent/job-profiles", headers=headers)
    assert listed.status_code == 200
    listed_payload = listed.json()
    assert any(v["id"] == "nightly" for v in listed_payload["job_profiles"])

    revoked = await cl.delete("/api/v1/agent/job-profiles/nightly", headers=headers)
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "ok"


@pytest.mark.anyio
async def test_agent_job_profile_run_issues_lease(client, tmp_path, monkeypatch):
    cl, token = client
    monkeypatch.setattr(job_core, "APP_DIR", tmp_path)
    monkeypatch.setattr(lease_core, "APP_DIR", tmp_path)
    monkeypatch.setattr(export_policy, "APP_DIR", tmp_path)
    api.app.state.pm.current_fingerprint = "ABC123"
    api.app.state.pm.entry_manager.search_entries = lambda q: [
        (7, "Site", "user", "url", False, EntryType.PASSWORD)
    ]
    headers = {"Authorization": f"Bearer {token}"}
    created = await cl.post(
        "/api/v1/agent/job-profiles",
        headers=headers,
        json={"id": "nightly-run", "query": "Site", "auth_broker": "keyring"},
    )
    assert created.status_code == 200

    run = await cl.post(
        "/api/v1/agent/job-profiles/nightly-run/run",
        headers=headers,
        json={},
    )
    assert run.status_code == 200
    payload = run.json()
    assert payload["status"] == "ok"
    assert payload["mode"] == "lease_issued"
    assert payload["kind"] == "password"
    assert payload["lease_id"]


@pytest.mark.anyio
async def test_agent_job_profile_run_policy_mismatch_denied(
    client, tmp_path, monkeypatch
):
    cl, token = client
    monkeypatch.setattr(job_core, "APP_DIR", tmp_path)
    monkeypatch.setattr(lease_core, "APP_DIR", tmp_path)
    monkeypatch.setattr(export_policy, "APP_DIR", tmp_path)
    api.app.state.pm.current_fingerprint = "ABC123"
    api.app.state.pm.entry_manager.search_entries = lambda q: [
        (7, "Site", "user", "url", False, EntryType.PASSWORD)
    ]
    headers = {"Authorization": f"Bearer {token}"}
    created = await cl.post(
        "/api/v1/agent/job-profiles",
        headers=headers,
        json={"id": "policy-run", "query": "Site", "auth_broker": "keyring"},
    )
    assert created.status_code == 200
    (tmp_path / "agent_policy.json").write_text(
        json.dumps({"allow_kinds": ["totp"], "allow_export_import": False}),
        encoding="utf-8",
    )
    denied = await cl.post(
        "/api/v1/agent/job-profiles/policy-run/run",
        headers=headers,
        json={},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"] == "job_profile_policy_mismatch"

    allowed = await cl.post(
        "/api/v1/agent/job-profiles/policy-run/run",
        headers=headers,
        json={"allow_policy_drift": True},
    )
    assert allowed.status_code == 200
    assert allowed.json()["status"] == "ok"


@pytest.mark.anyio
async def test_agent_job_profile_template_endpoint(client, tmp_path, monkeypatch):
    cl, token = client
    monkeypatch.setattr(job_core, "APP_DIR", tmp_path)
    api.app.state.pm.current_fingerprint = "ABC123"
    headers = {"Authorization": f"Bearer {token}"}
    created = await cl.post(
        "/api/v1/agent/job-profiles",
        headers=headers,
        json={
            "id": "templated-job",
            "query": "Site",
            "auth_broker": "keyring",
            "schedule": "*/30 * * * *",
        },
    )
    assert created.status_code == 200

    cron = await cl.get(
        "/api/v1/agent/job-profiles/templated-job/template",
        headers=headers,
    )
    assert cron.status_code == 200
    cron_payload = cron.json()
    assert cron_payload["status"] == "ok"
    assert cron_payload["mode"] == "cron"
    assert cron_payload["schedule_source"] == "profile"
    assert "agent job-profile-run templated-job" in cron_payload["command"]
    assert cron_payload["cron_line"].startswith("*/30 * * * * ")

    systemd = await cl.get(
        "/api/v1/agent/job-profiles/templated-job/template",
        headers=headers,
        params={
            "mode": "systemd",
            "schedule": "*:0/20",
            "unit_name": "seedpass-nightly",
        },
    )
    assert systemd.status_code == 200
    systemd_payload = systemd.json()
    assert systemd_payload["mode"] == "systemd"
    assert systemd_payload["schedule_source"] == "provided"
    assert (
        "ExecStart=seedpass --fingerprint ABC123 agent job-profile-run templated-job"
        in systemd_payload["systemd_service"]
    )
    assert "OnCalendar=*:0/20" in systemd_payload["systemd_timer"]
    assert "template_manifest" in systemd_payload
    assert systemd_payload["template_manifest"]["job_profile_id"] == "templated-job"


@pytest.mark.anyio
async def test_agent_job_profile_template_post_and_verify(
    client, tmp_path, monkeypatch
):
    cl, token = client
    monkeypatch.setattr(job_core, "APP_DIR", tmp_path)
    api.app.state.pm.current_fingerprint = "ABC123"
    headers = {"Authorization": f"Bearer {token}"}
    created = await cl.post(
        "/api/v1/agent/job-profiles",
        headers=headers,
        json={"id": "verify-job", "query": "Site", "auth_broker": "keyring"},
    )
    assert created.status_code == 200

    rendered = await cl.post(
        "/api/v1/agent/job-profiles/verify-job/template",
        headers=headers,
        json={"mode": "cron", "schedule": "0 * * * *", "include_manifest": True},
    )
    assert rendered.status_code == 200
    rendered_payload = rendered.json()
    assert rendered_payload["status"] == "ok"
    assert rendered_payload["schedule"] == "0 * * * *"
    assert "template_manifest" in rendered_payload

    verified = await cl.post(
        "/api/v1/agent/job-profiles/verify-job/template/verify",
        headers=headers,
        json={"template": rendered_payload},
    )
    assert verified.status_code == 200
    verified_payload = verified.json()
    assert verified_payload["status"] == "ok"
    assert verified_payload["valid"] is True

    tampered = dict(rendered_payload)
    tampered["command"] = "seedpass --fingerprint ABC123 agent job-profile-run altered"
    bad = await cl.post(
        "/api/v1/agent/job-profiles/verify-job/template/verify",
        headers=headers,
        json={"template": tampered},
    )
    assert bad.status_code == 200
    bad_payload = bad.json()
    assert bad_payload["valid"] is False
    assert "template_hash_sha256" in bad_payload["mismatches"]


@pytest.mark.anyio
async def test_agent_recovery_split_recover_api(client, monkeypatch, tmp_path):
    cl, token = client
    monkeypatch.setattr(recovery_core, "APP_DIR", tmp_path)
    headers = {"Authorization": f"Bearer {token}"}
    secret = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    split = await cl.post(
        "/api/v1/agent/recovery/split",
        headers=headers,
        json={"secret": secret, "shares": 5, "threshold": 3, "label": "api-recovery"},
    )
    assert split.status_code == 200
    split_payload = split.json()
    assert split_payload["status"] == "ok"
    shares = split_payload["shares"]
    assert len(shares) == 5

    recover = await cl.post(
        "/api/v1/agent/recovery/recover",
        headers=headers,
        json={"shares": shares[:3], "reveal": True},
    )
    assert recover.status_code == 200
    recover_payload = recover.json()
    assert recover_payload["status"] == "ok"
    assert recover_payload["secret"] == secret


@pytest.mark.anyio
async def test_agent_recovery_drill_and_verify_api(client, monkeypatch, tmp_path):
    cl, token = client
    monkeypatch.setattr(recovery_core, "APP_DIR", tmp_path)
    headers = {"Authorization": f"Bearer {token}"}
    missing = tmp_path / "missing-backup.enc"

    drill = await cl.post(
        "/api/v1/agent/recovery/drill",
        headers=headers,
        json={"backup_path": str(missing), "simulated": True, "max_age_days": 7},
    )
    assert drill.status_code == 200
    drill_payload = drill.json()
    assert drill_payload["status"] == "ok"
    assert drill_payload["report"]["status"] == "warning"

    listed = await cl.get("/api/v1/agent/recovery/drills", headers=headers)
    assert listed.status_code == 200
    listed_payload = listed.json()
    assert listed_payload["count"] >= 1

    verify = await cl.post(
        "/api/v1/agent/recovery/drills/verify",
        headers=headers,
        json={"limit": 50},
    )
    assert verify.status_code == 200
    verify_payload = verify.json()
    assert verify_payload["status"] == "ok"
    assert verify_payload["valid"] is True


@pytest.mark.anyio
async def test_agent_recovery_drill_verify_detects_tamper(
    client, monkeypatch, tmp_path
):
    cl, token = client
    monkeypatch.setattr(recovery_core, "APP_DIR", tmp_path)
    headers = {"Authorization": f"Bearer {token}"}
    missing = tmp_path / "missing-backup.enc"

    created = await cl.post(
        "/api/v1/agent/recovery/drill",
        headers=headers,
        json={"backup_path": str(missing), "simulated": True},
    )
    assert created.status_code == 200

    log_path = tmp_path / "agent_recovery_drills.log"
    lines = [ln for ln in log_path.read_text(encoding="utf-8").splitlines() if ln]
    payload = json.loads(lines[-1])
    payload["backup_exists"] = True
    lines[-1] = json.dumps(payload, sort_keys=True)
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    verify = await cl.post(
        "/api/v1/agent/recovery/drills/verify",
        headers=headers,
        json={"limit": 50},
    )
    assert verify.status_code == 200
    verify_payload = verify.json()
    assert verify_payload["valid"] is False
    assert any("sig_mismatch_line" in v for v in verify_payload["errors"])


@pytest.mark.anyio
async def test_backup_parent_seed_blocked_when_high_risk_locked(
    client, tmp_path, monkeypatch
):
    cl, token = client
    api.app.state.pm.parent_seed = "seed"
    api.app.state.pm.current_fingerprint = "ABC123"
    api.app.state.pm.encryption_manager = SimpleNamespace(
        encrypt_and_save_file=lambda data, path: None,
        resolve_relative_path=lambda p: p,
    )
    monkeypatch.setattr(export_policy, "APP_DIR", tmp_path)
    monkeypatch.setattr(isolation_core, "APP_DIR", tmp_path)
    isolation_core.set_high_risk_factor("factor-xyz")
    (tmp_path / "agent_policy.json").write_text(
        json.dumps(
            {"secret_isolation": {"enabled": True, "high_risk_kinds": ["seed"]}}
        ),
        encoding="utf-8",
    )
    headers = {
        "Authorization": f"Bearer {token}",
        "X-SeedPass-Password": "pw",
    }
    res = await cl.post(
        "/api/v1/vault/backup-parent-seed",
        json={"path": "seed.enc", "confirm": True},
        headers=headers,
    )
    assert res.status_code == 403
    assert res.json()["detail"] == "policy_deny:high_risk_locked"


@pytest.mark.anyio
async def test_backup_parent_seed_requires_approval_when_agent_profile(
    client, tmp_path, monkeypatch
):
    cl, token = client
    api.app.state.pm.parent_seed = "seed"
    api.app.state.pm.encryption_manager = SimpleNamespace(
        encrypt_and_save_file=lambda data, path: None,
        resolve_relative_path=lambda p: p,
    )
    monkeypatch.setattr(export_policy, "APP_DIR", tmp_path)
    monkeypatch.setattr(approval_core, "APP_DIR", tmp_path)
    (tmp_path / "agent_policy.json").write_text(
        json.dumps({"approvals": {"require_for": ["reveal_parent_seed"]}}),
        encoding="utf-8",
    )
    headers = {
        "Authorization": f"Bearer {token}",
        "X-SeedPass-Password": "pw",
        "X-SeedPass-Agent-Profile": "true",
    }
    res = await cl.post(
        "/api/v1/vault/backup-parent-seed",
        json={"path": "seed.enc", "confirm": True},
        headers=headers,
    )
    assert res.status_code == 403
    assert res.json()["detail"] == "policy_deny:approval_required"


@pytest.mark.anyio
async def test_backup_parent_seed_allows_with_approval_when_agent_profile(
    client, tmp_path, monkeypatch
):
    cl, token = client
    api.app.state.pm.parent_seed = "seed"
    called = {}
    api.app.state.pm.encryption_manager = SimpleNamespace(
        encrypt_and_save_file=lambda data, path: called.setdefault("path", path),
        resolve_relative_path=lambda p: p,
    )
    monkeypatch.setattr(export_policy, "APP_DIR", tmp_path)
    monkeypatch.setattr(approval_core, "APP_DIR", tmp_path)
    (tmp_path / "agent_policy.json").write_text(
        json.dumps({"approvals": {"require_for": ["reveal_parent_seed"]}}),
        encoding="utf-8",
    )
    approval = approval_core.issue_approval(
        action="reveal_parent_seed",
        ttl_seconds=300,
        uses=1,
        resource="vault:parent-seed",
    )
    headers = {
        "Authorization": f"Bearer {token}",
        "X-SeedPass-Password": "pw",
        "X-SeedPass-Agent-Profile": "true",
        "X-SeedPass-Approval-Id": approval["id"],
    }
    res = await cl.post(
        "/api/v1/vault/backup-parent-seed",
        json={"path": "seed.enc", "confirm": True},
        headers=headers,
    )
    assert res.status_code == 200
    assert res.json() == {"status": "saved", "path": "seed.enc"}
    assert str(called["path"]) == "seed.enc"


@pytest.mark.anyio
async def test_backup_parent_seed_path_traversal_blocked(client, tmp_path):
    cl, token = client
    api.app.state.pm.parent_seed = "seed"
    key = base64.urlsafe_b64encode(os.urandom(32))
    api.app.state.pm.encryption_manager = EncryptionManager(key, tmp_path)
    headers = {
        "Authorization": f"Bearer {token}",
        "X-SeedPass-Password": "pw",
    }
    res = await cl.post(
        "/api/v1/vault/backup-parent-seed",
        json={"path": "../evil.enc", "confirm": True},
        headers=headers,
    )
    assert res.status_code == 400


@pytest.mark.anyio
async def test_relay_management_endpoints(client, dummy_nostr_client, monkeypatch):
    cl, token = client
    nostr_client, _ = dummy_nostr_client
    relays = ["wss://a", "wss://b"]

    def load_config(require_pin=False):
        return {"relays": relays.copy()}

    called = {}

    def set_relays(new, require_pin=False):
        called["set"] = new

    api.app.state.pm.config_manager.load_config = load_config
    api.app.state.pm.config_manager.set_relays = set_relays
    monkeypatch.setattr(
        NostrClient,
        "initialize_client_pool",
        lambda self: called.setdefault("init", True),
    )
    monkeypatch.setattr(
        nostr_client, "close_client_pool", lambda: called.setdefault("close", True)
    )
    api.app.state.pm.nostr_client = nostr_client
    api.app.state.pm.nostr_client.relays = relays.copy()

    headers = {"Authorization": f"Bearer {token}"}

    res = await cl.get("/api/v1/relays", headers=headers)
    assert res.status_code == 200
    assert res.json() == {"relays": relays}

    res = await cl.post("/api/v1/relays", json={"url": "wss://c"}, headers=headers)
    assert res.status_code == 200
    assert called["set"] == ["wss://a", "wss://b", "wss://c"]

    api.app.state.pm.config_manager.load_config = lambda require_pin=False: {
        "relays": ["wss://a", "wss://b", "wss://c"]
    }
    res = await cl.delete("/api/v1/relays/2", headers=headers)
    assert res.status_code == 200
    assert called["set"] == ["wss://a", "wss://c"]

    res = await cl.post("/api/v1/relays/reset", headers=headers)
    assert res.status_code == 200
    assert called.get("init") is True
    assert api.app.state.pm.nostr_client.relays == list(DEFAULT_RELAYS)


@pytest.mark.anyio
async def test_generate_password_no_special_chars(client):
    cl, token = client

    class DummyEnc:
        def derive_seed_from_mnemonic(self, mnemonic):
            return b"\x00" * 32

    class DummyBIP85:
        def derive_entropy(
            self, index: int, entropy_bytes: int, app_no: int = 32
        ) -> bytes:
            return bytes(range(entropy_bytes))

    api.app.state.pm.password_generator = PasswordGenerator(
        DummyEnc(), "seed", DummyBIP85()
    )
    api.app.state.pm.parent_seed = "seed"

    headers = {"Authorization": f"Bearer {token}"}
    res = await cl.post(
        "/api/v1/password",
        json={"length": 16, "include_special_chars": False},
        headers=headers,
    )
    assert res.status_code == 200
    pw = res.json()["password"]
    assert not any(c in string.punctuation for c in pw)


@pytest.mark.anyio
async def test_generate_password_allowed_chars(client):
    cl, token = client

    class DummyEnc:
        def derive_seed_from_mnemonic(self, mnemonic):
            return b"\x00" * 32

    class DummyBIP85:
        def derive_entropy(
            self, index: int, entropy_bytes: int, app_no: int = 32
        ) -> bytes:
            return bytes((index + i) % 256 for i in range(entropy_bytes))

    api.app.state.pm.password_generator = PasswordGenerator(
        DummyEnc(), "seed", DummyBIP85()
    )
    api.app.state.pm.parent_seed = "seed"

    headers = {"Authorization": f"Bearer {token}"}
    allowed = "@$"
    res = await cl.post(
        "/api/v1/password",
        json={"length": 16, "allowed_special_chars": allowed},
        headers=headers,
    )
    assert res.status_code == 200
    pw = res.json()["password"]
    specials = [c for c in pw if c in string.punctuation]
    assert specials and all(c in allowed for c in specials)
