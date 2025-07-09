from types import SimpleNamespace
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
