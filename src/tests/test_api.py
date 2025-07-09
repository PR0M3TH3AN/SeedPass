from types import SimpleNamespace
from pathlib import Path
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass import api


@pytest.fixture
def client(monkeypatch):
    dummy = SimpleNamespace(
        entry_manager=SimpleNamespace(
            search_entries=lambda q: [(1, "Site", "user", "url", False)],
            retrieve_entry=lambda i: {"label": "Site"},
            add_entry=lambda *a, **k: 1,
            modify_entry=lambda *a, **k: None,
            archive_entry=lambda i: None,
            restore_entry=lambda i: None,
        ),
        config_manager=SimpleNamespace(
            load_config=lambda require_pin=False: {"k": "v"}
        ),
        fingerprint_manager=SimpleNamespace(list_fingerprints=lambda: ["fp"]),
        nostr_client=SimpleNamespace(
            key_manager=SimpleNamespace(get_npub=lambda: "np")
        ),
    )
    monkeypatch.setattr(api, "PasswordManager", lambda: dummy)
    monkeypatch.setenv("SEEDPASS_CORS_ORIGINS", "http://example.com")
    token = api.start_server()
    client = TestClient(api.app)
    return client, token


def test_cors_and_auth(client):
    cl, token = client
    headers = {"Authorization": f"Bearer {token}", "Origin": "http://example.com"}
    res = cl.get("/api/v1/entry", params={"query": "s"}, headers=headers)
    assert res.status_code == 200
    assert res.headers.get("access-control-allow-origin") == "http://example.com"


def test_invalid_token(client):
    cl, _token = client
    res = cl.get(
        "/api/v1/entry",
        params={"query": "s"},
        headers={"Authorization": "Bearer bad"},
    )
    assert res.status_code == 401


def test_get_entry_by_id(client):
    cl, token = client
    headers = {
        "Authorization": f"Bearer {token}",
        "Origin": "http://example.com",
    }
    res = cl.get("/api/v1/entry/1", headers=headers)
    assert res.status_code == 200
    assert res.json() == {"label": "Site"}
    assert res.headers.get("access-control-allow-origin") == "http://example.com"


def test_get_config_value(client):
    cl, token = client
    headers = {
        "Authorization": f"Bearer {token}",
        "Origin": "http://example.com",
    }
    res = cl.get("/api/v1/config/k", headers=headers)
    assert res.status_code == 200
    assert res.json() == {"key": "k", "value": "v"}
    assert res.headers.get("access-control-allow-origin") == "http://example.com"


def test_list_fingerprint(client):
    cl, token = client
    headers = {
        "Authorization": f"Bearer {token}",
        "Origin": "http://example.com",
    }
    res = cl.get("/api/v1/fingerprint", headers=headers)
    assert res.status_code == 200
    assert res.json() == ["fp"]
    assert res.headers.get("access-control-allow-origin") == "http://example.com"


def test_get_nostr_pubkey(client):
    cl, token = client
    headers = {
        "Authorization": f"Bearer {token}",
        "Origin": "http://example.com",
    }
    res = cl.get("/api/v1/nostr/pubkey", headers=headers)
    assert res.status_code == 200
    assert res.json() == {"npub": "np"}
    assert res.headers.get("access-control-allow-origin") == "http://example.com"


def test_create_modify_archive_entry(client):
    cl, token = client
    headers = {"Authorization": f"Bearer {token}", "Origin": "http://example.com"}

    res = cl.post(
        "/api/v1/entry",
        json={"label": "test", "length": 12},
        headers=headers,
    )
    assert res.status_code == 200
    assert res.json() == {"id": 1}

    res = cl.put(
        "/api/v1/entry/1",
        json={"username": "bob"},
        headers=headers,
    )
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}

    res = cl.post("/api/v1/entry/1/archive", headers=headers)
    assert res.status_code == 200
    assert res.json() == {"status": "archived"}

    res = cl.post("/api/v1/entry/1/unarchive", headers=headers)
    assert res.status_code == 200
    assert res.json() == {"status": "active"}


def test_shutdown(client, monkeypatch):
    cl, token = client

    calls = {}

    class Loop:
        def call_soon(self, func, *args):
            calls["func"] = func
            calls["args"] = args

    monkeypatch.setattr(api.asyncio, "get_event_loop", lambda: Loop())

    headers = {
        "Authorization": f"Bearer {token}",
        "Origin": "http://example.com",
    }
    res = cl.post("/api/v1/shutdown", headers=headers)
    assert res.status_code == 200
    assert res.json() == {"status": "shutting down"}
    assert calls["func"] is sys.exit
    assert calls["args"] == (0,)
    assert res.headers.get("access-control-allow-origin") == "http://example.com"


@pytest.mark.parametrize(
    "method,path",
    [
        ("get", "/api/v1/entry/1"),
        ("get", "/api/v1/config/k"),
        ("get", "/api/v1/fingerprint"),
        ("get", "/api/v1/nostr/pubkey"),
        ("post", "/api/v1/shutdown"),
        ("post", "/api/v1/entry"),
        ("put", "/api/v1/entry/1"),
        ("post", "/api/v1/entry/1/archive"),
        ("post", "/api/v1/entry/1/unarchive"),
    ],
)
def test_invalid_token_other_endpoints(client, method, path):
    cl, _token = client
    req = getattr(cl, method)
    kwargs = {"headers": {"Authorization": "Bearer bad"}}
    if method in {"post", "put"}:
        kwargs["json"] = {}
    res = req(path, **kwargs)
    assert res.status_code == 401
