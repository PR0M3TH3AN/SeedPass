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
