import importlib
from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient

import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))


def test_rate_limit_exceeded(monkeypatch):
    monkeypatch.setenv("SEEDPASS_RATE_LIMIT", "2")
    monkeypatch.setenv("SEEDPASS_RATE_WINDOW", "60")
    import seedpass.api as api

    importlib.reload(api)

    dummy = SimpleNamespace(
        entry_manager=SimpleNamespace(
            search_entries=lambda q: [
                (1, "Site", "user", "url", False, SimpleNamespace(value="password"))
            ]
        ),
        config_manager=SimpleNamespace(load_config=lambda require_pin=False: {}),
        fingerprint_manager=SimpleNamespace(list_fingerprints=lambda: []),
        nostr_client=SimpleNamespace(
            key_manager=SimpleNamespace(get_npub=lambda: "np")
        ),
        verify_password=lambda pw: True,
    )
    monkeypatch.setattr(api, "PasswordManager", lambda: dummy)
    token = api.start_server()
    client = TestClient(api.app)
    headers = {"Authorization": f"Bearer {token}"}

    for _ in range(2):
        res = client.get("/api/v1/entry", params={"query": "s"}, headers=headers)
        assert res.status_code == 200

    res = client.get("/api/v1/entry", params={"query": "s"}, headers=headers)
    assert res.status_code == 429
