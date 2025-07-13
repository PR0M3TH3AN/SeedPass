import time
from types import SimpleNamespace

from password_manager.manager import PasswordManager


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
    time.sleep(0.05)
    assert called["sync"] is False
