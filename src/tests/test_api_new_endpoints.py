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
