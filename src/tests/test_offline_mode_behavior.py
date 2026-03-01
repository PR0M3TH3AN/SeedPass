import time
from types import SimpleNamespace

from seedpass.core.manager import PasswordManager


def test_sync_vault_skips_network(monkeypatch):
    pm = PasswordManager.__new__(PasswordManager)
    pm.offline_mode = True
    pm.get_encrypted_data = lambda: b"data"
    called = {"nostr": False}
    pm.nostr_client = SimpleNamespace(
        publish_snapshot=lambda *a, **kw: called.__setitem__("nostr", True)
    )
    result = PasswordManager.sync_vault(pm)
    assert result is None
    assert called["nostr"] is False


def test_start_background_sync_offline(monkeypatch):
    pm = PasswordManager.__new__(PasswordManager)
    pm.offline_mode = True
    called = {"sync": False}
    pm.sync_index_from_nostr = lambda: called.__setitem__("sync", True)
    PasswordManager.start_background_sync(pm)
    assert called["sync"] is False


def test_sync_vault_sets_last_error_on_exception():
    pm = PasswordManager.__new__(PasswordManager)
    pm.offline_mode = False
    pm.get_encrypted_data = lambda: b"data"
    pm.state_manager = None

    async def boom(_data):
        raise RuntimeError("relay write failed")

    pm.nostr_client = SimpleNamespace(
        publish_snapshot=boom,
        get_delta_events=lambda: [],
        last_error=None,
    )

    result = PasswordManager.sync_vault(pm)
    assert result is None
    assert pm.nostr_client.last_error == "relay write failed"
