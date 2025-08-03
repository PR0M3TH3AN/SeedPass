from types import SimpleNamespace
from pathlib import Path
import pytest

from seedpass import api
from test_api import client
from helpers import dummy_nostr_client
import string
from seedpass.core.password_generation import PasswordGenerator, PasswordPolicy
from nostr.client import NostrClient, DEFAULT_RELAYS


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


def test_update_entry_error(client):
    cl, token = client

    def modify(*a, **k):
        raise ValueError("nope")

    api._pm.entry_manager.modify_entry = modify
    headers = {"Authorization": f"Bearer {token}"}
    res = cl.put("/api/v1/entry/1", json={"username": "x"}, headers=headers)
    assert res.status_code == 400
    assert res.json() == {"detail": "nope"}


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
    api._pm.sync_vault = lambda: called.setdefault("sync", True)
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
    assert called.get("sync") is True


def test_vault_import_via_upload(client, tmp_path):
    cl, token = client
    called = {}

    def import_db(path):
        called["path"] = path

    api._pm.handle_import_database = import_db
    api._pm.sync_vault = lambda: called.setdefault("sync", True)
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
    assert called.get("sync") is True


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
    api._pm.unlock_vault = lambda pw: setattr(api._pm, "locked", False)
    api._pm.unlock_vault("pw")
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


def test_vault_export_endpoint(client, tmp_path):
    cl, token = client
    out = tmp_path / "out.json"
    out.write_text("data")

    api._pm.handle_export_database = lambda: out

    headers = {"Authorization": f"Bearer {token}"}
    res = cl.post("/api/v1/vault/export", headers=headers)
    assert res.status_code == 200
    assert res.content == b"data"


def test_backup_parent_seed_endpoint(client, tmp_path):
    cl, token = client
    called = {}

    def backup(path=None):
        called["path"] = path

    api._pm.handle_backup_reveal_parent_seed = backup
    path = tmp_path / "seed.enc"
    headers = {"Authorization": f"Bearer {token}"}
    res = cl.post(
        "/api/v1/vault/backup-parent-seed",
        json={"path": str(path)},
        headers=headers,
    )
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}
    assert called["path"] == path


def test_relay_management_endpoints(client, dummy_nostr_client, monkeypatch):
    cl, token = client
    nostr_client, _ = dummy_nostr_client
    relays = ["wss://a", "wss://b"]

    def load_config(require_pin=False):
        return {"relays": relays.copy()}

    called = {}

    def set_relays(new, require_pin=False):
        called["set"] = new

    api._pm.config_manager.load_config = load_config
    api._pm.config_manager.set_relays = set_relays
    monkeypatch.setattr(
        NostrClient,
        "initialize_client_pool",
        lambda self: called.setdefault("init", True),
    )
    monkeypatch.setattr(
        nostr_client, "close_client_pool", lambda: called.setdefault("close", True)
    )
    api._pm.nostr_client = nostr_client
    api._pm.nostr_client.relays = relays.copy()

    headers = {"Authorization": f"Bearer {token}"}

    res = cl.get("/api/v1/relays", headers=headers)
    assert res.status_code == 200
    assert res.json() == {"relays": relays}

    res = cl.post("/api/v1/relays", json={"url": "wss://c"}, headers=headers)
    assert res.status_code == 200
    assert called["set"] == ["wss://a", "wss://b", "wss://c"]

    api._pm.config_manager.load_config = lambda require_pin=False: {
        "relays": ["wss://a", "wss://b", "wss://c"]
    }
    res = cl.delete("/api/v1/relays/2", headers=headers)
    assert res.status_code == 200
    assert called["set"] == ["wss://a", "wss://c"]

    res = cl.post("/api/v1/relays/reset", headers=headers)
    assert res.status_code == 200
    assert called.get("init") is True
    assert api._pm.nostr_client.relays == list(DEFAULT_RELAYS)


def test_generate_password_no_special_chars(client):
    cl, token = client

    class DummyEnc:
        def derive_seed_from_mnemonic(self, mnemonic):
            return b"\x00" * 32

    class DummyBIP85:
        def derive_entropy(self, index: int, bytes_len: int, app_no: int = 32) -> bytes:
            return bytes(range(bytes_len))

    api._pm.password_generator = PasswordGenerator(DummyEnc(), "seed", DummyBIP85())
    api._pm.parent_seed = "seed"

    headers = {"Authorization": f"Bearer {token}"}
    res = cl.post(
        "/api/v1/password",
        json={"length": 16, "include_special_chars": False},
        headers=headers,
    )
    assert res.status_code == 200
    pw = res.json()["password"]
    assert not any(c in string.punctuation for c in pw)


def test_generate_password_allowed_chars(client):
    cl, token = client

    class DummyEnc:
        def derive_seed_from_mnemonic(self, mnemonic):
            return b"\x00" * 32

    class DummyBIP85:
        def derive_entropy(self, index: int, bytes_len: int, app_no: int = 32) -> bytes:
            return bytes((index + i) % 256 for i in range(bytes_len))

    api._pm.password_generator = PasswordGenerator(DummyEnc(), "seed", DummyBIP85())
    api._pm.parent_seed = "seed"

    headers = {"Authorization": f"Bearer {token}"}
    allowed = "@$"
    res = cl.post(
        "/api/v1/password",
        json={"length": 16, "allowed_special_chars": allowed},
        headers=headers,
    )
    assert res.status_code == 200
    pw = res.json()["password"]
    specials = [c for c in pw if c in string.punctuation]
    assert specials and all(c in allowed for c in specials)
