from types import SimpleNamespace
from pathlib import Path
import pytest

from seedpass import api
from test_api import client


def test_create_and_modify_totp_entry(client):
    cl, token = client
    calls = {}

    def add_totp(label, seed, **kwargs):
        calls["create"] = kwargs
        return "uri"

    def modify(idx, **kwargs):
        calls["modify"] = (idx, kwargs)

    api._pm.entry_manager.add_totp = add_totp
    api._pm.entry_manager.modify_entry = modify
    api._pm.entry_manager.get_next_index = lambda: 5
    api._pm.parent_seed = "seed"

    headers = {"Authorization": f"Bearer {token}"}
    res = cl.post(
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
    }

    res = cl.put(
        "/api/v1/entry/5",
        json={"period": 90, "digits": 6},
        headers=headers,
    )
    assert res.status_code == 200
    assert calls["modify"][0] == 5
    assert calls["modify"][1]["period"] == 90
    assert calls["modify"][1]["digits"] == 6


def test_create_and_modify_ssh_entry(client):
    cl, token = client
    calls = {}

    def add_ssh(label, seed, **kwargs):
        calls["create"] = kwargs
        return 2

    def modify(idx, **kwargs):
        calls["modify"] = (idx, kwargs)

    api._pm.entry_manager.add_ssh_key = add_ssh
    api._pm.entry_manager.modify_entry = modify
    api._pm.parent_seed = "seed"

    headers = {"Authorization": f"Bearer {token}"}
    res = cl.post(
        "/api/v1/entry",
        json={"type": "ssh", "label": "S", "index": 2, "notes": "n"},
        headers=headers,
    )
    assert res.status_code == 200
    assert res.json() == {"id": 2}
    assert calls["create"] == {"index": 2, "notes": "n", "archived": False}

    res = cl.put(
        "/api/v1/entry/2",
        json={"notes": "x"},
        headers=headers,
    )
    assert res.status_code == 200
    assert calls["modify"][0] == 2
    assert calls["modify"][1]["notes"] == "x"


def test_update_config_secret_mode(client):
    cl, token = client
    called = {}

    def set_secret(val):
        called["val"] = val

    api._pm.config_manager.set_secret_mode_enabled = set_secret
    headers = {"Authorization": f"Bearer {token}"}
    res = cl.put(
        "/api/v1/config/secret_mode_enabled",
        json={"value": True},
        headers=headers,
    )
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}
    assert called["val"] is True


def test_totp_export_endpoint(client):
    cl, token = client
    api._pm.entry_manager.export_totp_entries = lambda seed: {"entries": ["x"]}
    api._pm.parent_seed = "seed"
    headers = {"Authorization": f"Bearer {token}"}
    res = cl.get("/api/v1/totp/export", headers=headers)
    assert res.status_code == 200
    assert res.json() == {"entries": ["x"]}


def test_totp_codes_endpoint(client):
    cl, token = client
    api._pm.entry_manager.list_entries = lambda **kw: [(0, "Email", None, None, False)]
    api._pm.entry_manager.get_totp_code = lambda i, s: "123456"
    api._pm.entry_manager.get_totp_time_remaining = lambda i: 30
    api._pm.parent_seed = "seed"
    headers = {"Authorization": f"Bearer {token}"}
    res = cl.get("/api/v1/totp", headers=headers)
    assert res.status_code == 200
    assert res.json() == {
        "codes": [
            {"id": 0, "label": "Email", "code": "123456", "seconds_remaining": 30}
        ]
    }


def test_parent_seed_endpoint(client, tmp_path):
    cl, token = client
    api._pm.parent_seed = "seed"
    called = {}
    api._pm.encryption_manager = SimpleNamespace(
        encrypt_and_save_file=lambda data, path: called.setdefault("path", path)
    )
    headers = {"Authorization": f"Bearer {token}"}

    res = cl.get("/api/v1/parent-seed", headers=headers)
    assert res.status_code == 200
    assert res.json() == {"seed": "seed"}

    out = tmp_path / "bk.enc"
    res = cl.get("/api/v1/parent-seed", params={"file": str(out)}, headers=headers)
    assert res.status_code == 200
    assert res.json() == {"status": "saved", "path": str(out)}
    assert called["path"] == out


def test_fingerprint_endpoints(client):
    cl, token = client
    calls = {}

    api._pm.add_new_fingerprint = lambda: calls.setdefault("add", True)
    api._pm.fingerprint_manager.remove_fingerprint = lambda fp: calls.setdefault(
        "remove", fp
    )
    api._pm.select_fingerprint = lambda fp: calls.setdefault("select", fp)

    headers = {"Authorization": f"Bearer {token}"}

    res = cl.post("/api/v1/fingerprint", headers=headers)
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}
    assert calls.get("add") is True

    res = cl.delete("/api/v1/fingerprint/abc", headers=headers)
    assert res.status_code == 200
    assert res.json() == {"status": "deleted"}
    assert calls.get("remove") == "abc"

    res = cl.post(
        "/api/v1/fingerprint/select",
        json={"fingerprint": "xyz"},
        headers=headers,
    )
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}
    assert calls.get("select") == "xyz"


def test_checksum_endpoints(client):
    cl, token = client
    calls = {}

    api._pm.handle_verify_checksum = lambda: calls.setdefault("verify", True)
    api._pm.handle_update_script_checksum = lambda: calls.setdefault("update", True)

    headers = {"Authorization": f"Bearer {token}"}

    res = cl.post("/api/v1/checksum/verify", headers=headers)
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}
    assert calls.get("verify") is True

    res = cl.post("/api/v1/checksum/update", headers=headers)
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}
    assert calls.get("update") is True


def test_vault_import_via_path(client, tmp_path):
    cl, token = client
    called = {}

    def import_db(path):
        called["path"] = path

    api._pm.handle_import_database = import_db
    file_path = tmp_path / "b.json"
    file_path.write_text("{}")

    headers = {"Authorization": f"Bearer {token}"}
    res = cl.post(
        "/api/v1/vault/import",
        json={"path": str(file_path)},
        headers=headers,
    )
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}
    assert called["path"] == file_path


def test_vault_import_via_upload(client, tmp_path):
    cl, token = client
    called = {}

    def import_db(path):
        called["path"] = path

    api._pm.handle_import_database = import_db
    file_path = tmp_path / "c.json"
    file_path.write_text("{}")

    headers = {"Authorization": f"Bearer {token}"}
    with open(file_path, "rb") as fh:
        res = cl.post(
            "/api/v1/vault/import",
            files={"file": ("c.json", fh.read())},
            headers=headers,
        )
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}
    assert isinstance(called.get("path"), Path)


def test_vault_lock_endpoint(client):
    cl, token = client
    called = {}

    def lock():
        called["locked"] = True
        api._pm.locked = True

    api._pm.lock_vault = lock
    api._pm.locked = False

    headers = {"Authorization": f"Bearer {token}"}
    res = cl.post("/api/v1/vault/lock", headers=headers)
    assert res.status_code == 200
    assert res.json() == {"status": "locked"}
    assert called.get("locked") is True
    assert api._pm.locked is True
    api._pm.unlock_vault = lambda: setattr(api._pm, "locked", False)
    api._pm.unlock_vault()
    assert api._pm.locked is False


def test_secret_mode_endpoint(client):
    cl, token = client
    called = {}

    def set_secret(val):
        called.setdefault("enabled", val)

    def set_delay(val):
        called.setdefault("delay", val)

    api._pm.config_manager.set_secret_mode_enabled = set_secret
    api._pm.config_manager.set_clipboard_clear_delay = set_delay

    headers = {"Authorization": f"Bearer {token}"}
    res = cl.post(
        "/api/v1/secret-mode",
        json={"enabled": True, "delay": 12},
        headers=headers,
    )
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}
    assert called["enabled"] is True
    assert called["delay"] == 12
