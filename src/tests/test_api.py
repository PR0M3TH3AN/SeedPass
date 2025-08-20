from types import SimpleNamespace
from pathlib import Path
import sys

import pytest
from httpx import ASGITransport, AsyncClient
import bcrypt

sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass import api
from seedpass.core.entry_types import EntryType


@pytest.fixture
async def client(monkeypatch):
    dummy = SimpleNamespace(
        entry_manager=SimpleNamespace(
            search_entries=lambda q: [
                (1, "Site", "user", "url", False, EntryType.PASSWORD)
            ],
            retrieve_entry=lambda i: {"label": "Site"},
            add_entry=lambda *a, **k: 1,
            modify_entry=lambda *a, **k: None,
            archive_entry=lambda i: None,
            restore_entry=lambda i: None,
        ),
        config_manager=SimpleNamespace(
            load_config=lambda require_pin=False: {"k": "v"},
            set_pin=lambda v: None,
            set_password_hash=lambda v: None,
            set_relays=lambda v, require_pin=False: None,
            set_inactivity_timeout=lambda v: None,
            set_additional_backup_path=lambda v: None,
            set_secret_mode_enabled=lambda v: None,
            set_clipboard_clear_delay=lambda v: None,
            set_quick_unlock=lambda v: None,
        ),
        fingerprint_manager=SimpleNamespace(list_fingerprints=lambda: ["fp"]),
        nostr_client=SimpleNamespace(
            key_manager=SimpleNamespace(get_npub=lambda: "np")
        ),
        verify_password=lambda pw: True,
    )
    monkeypatch.setattr(api, "PasswordManager", lambda: dummy)
    monkeypatch.setenv("SEEDPASS_CORS_ORIGINS", "http://example.com")
    token = api.start_server()
    transport = ASGITransport(app=api.app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac, token


@pytest.mark.anyio
async def test_token_hashed(client):
    _, token = client
    assert api.app.state.token_hash != token
    assert bcrypt.checkpw(token.encode(), api.app.state.token_hash)


@pytest.mark.anyio
async def test_cors_and_auth(client):
    cl, token = client
    headers = {"Authorization": f"Bearer {token}", "Origin": "http://example.com"}
    res = await cl.get("/api/v1/entry", params={"query": "s"}, headers=headers)
    assert res.status_code == 200
    assert res.headers.get("access-control-allow-origin") == "http://example.com"


@pytest.mark.anyio
async def test_invalid_token(client):
    cl, _token = client
    res = await cl.get(
        "/api/v1/entry",
        params={"query": "s"},
        headers={"Authorization": "Bearer bad"},
    )
    assert res.status_code == 401


@pytest.mark.anyio
async def test_get_entry_by_id(client):
    cl, token = client
    headers = {
        "Authorization": f"Bearer {token}",
        "Origin": "http://example.com",
        "X-SeedPass-Password": "pw",
    }
    res = await cl.get("/api/v1/entry/1", headers=headers)
    assert res.status_code == 200
    assert res.json() == {"label": "Site"}
    assert res.headers.get("access-control-allow-origin") == "http://example.com"


@pytest.mark.anyio
async def test_get_config_value(client):
    cl, token = client
    headers = {
        "Authorization": f"Bearer {token}",
        "Origin": "http://example.com",
    }
    res = await cl.get("/api/v1/config/k", headers=headers)
    assert res.status_code == 200
    assert res.json() == {"key": "k", "value": "v"}
    assert res.headers.get("access-control-allow-origin") == "http://example.com"


@pytest.mark.anyio
async def test_list_fingerprint(client):
    cl, token = client
    headers = {
        "Authorization": f"Bearer {token}",
        "Origin": "http://example.com",
    }
    res = await cl.get("/api/v1/fingerprint", headers=headers)
    assert res.status_code == 200
    assert res.json() == ["fp"]
    assert res.headers.get("access-control-allow-origin") == "http://example.com"


@pytest.mark.anyio
async def test_get_nostr_pubkey(client):
    cl, token = client
    headers = {
        "Authorization": f"Bearer {token}",
        "Origin": "http://example.com",
    }
    res = await cl.get("/api/v1/nostr/pubkey", headers=headers)
    assert res.status_code == 200
    assert res.json() == {"npub": "np"}
    assert res.headers.get("access-control-allow-origin") == "http://example.com"


@pytest.mark.anyio
async def test_create_modify_archive_entry(client):
    cl, token = client
    headers = {"Authorization": f"Bearer {token}", "Origin": "http://example.com"}

    res = await cl.post(
        "/api/v1/entry",
        json={"label": "test", "length": 12},
        headers=headers,
    )
    assert res.status_code == 200
    assert res.json() == {"id": 1}

    res = await cl.put(
        "/api/v1/entry/1",
        json={"username": "bob"},
        headers=headers,
    )
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}

    res = await cl.post("/api/v1/entry/1/archive", headers=headers)
    assert res.status_code == 200
    assert res.json() == {"status": "archived"}

    res = await cl.post("/api/v1/entry/1/unarchive", headers=headers)
    assert res.status_code == 200
    assert res.json() == {"status": "active"}


@pytest.mark.anyio
async def test_update_config(client):
    cl, token = client
    called = {}

    def set_timeout(val):
        called["val"] = val

    api.app.state.pm.config_manager.set_inactivity_timeout = set_timeout
    headers = {"Authorization": f"Bearer {token}", "Origin": "http://example.com"}
    res = await cl.put(
        "/api/v1/config/inactivity_timeout",
        json={"value": 42},
        headers=headers,
    )
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}
    assert called["val"] == 42
    assert res.headers.get("access-control-allow-origin") == "http://example.com"


@pytest.mark.anyio
async def test_update_config_quick_unlock(client):
    cl, token = client
    called = {}
    api.app.state.pm.config_manager.set_quick_unlock = lambda v: called.setdefault(
        "val", v
    )
    headers = {"Authorization": f"Bearer {token}", "Origin": "http://example.com"}
    res = await cl.put(
        "/api/v1/config/quick_unlock",
        json={"value": True},
        headers=headers,
    )
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}
    assert called.get("val") is True


@pytest.mark.anyio
async def test_change_password_route(client):
    cl, token = client
    called = {}
    api.app.state.pm.change_password = lambda o, n: called.setdefault("called", (o, n))
    headers = {"Authorization": f"Bearer {token}", "Origin": "http://example.com"}
    res = await cl.post(
        "/api/v1/change-password",
        headers=headers,
        json={"old": "old", "new": "new"},
    )
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}
    assert called.get("called") == ("old", "new")
    assert res.headers.get("access-control-allow-origin") == "http://example.com"


@pytest.mark.anyio
async def test_update_config_unknown_key(client):
    cl, token = client
    headers = {"Authorization": f"Bearer {token}", "Origin": "http://example.com"}
    res = await cl.put(
        "/api/v1/config/bogus",
        json={"value": 1},
        headers=headers,
    )
    assert res.status_code == 400


@pytest.mark.anyio
async def test_shutdown(client, monkeypatch):
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
    res = await cl.post("/api/v1/shutdown", headers=headers)
    assert res.status_code == 200
    assert res.json() == {"status": "shutting down"}
    assert calls["func"] is sys.exit
    assert calls["args"] == (0,)
    assert res.headers.get("access-control-allow-origin") == "http://example.com"


@pytest.mark.anyio
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
        ("put", "/api/v1/config/inactivity_timeout"),
        ("post", "/api/v1/entry/1/archive"),
        ("post", "/api/v1/entry/1/unarchive"),
        ("post", "/api/v1/change-password"),
        ("post", "/api/v1/vault/lock"),
    ],
)
async def test_invalid_token_other_endpoints(client, method, path):
    cl, _token = client
    req = getattr(cl, method)
    kwargs = {"headers": {"Authorization": "Bearer bad"}}
    if method in {"post", "put"}:
        kwargs["json"] = {}
    res = await req(path, **kwargs)
    assert res.status_code == 401
