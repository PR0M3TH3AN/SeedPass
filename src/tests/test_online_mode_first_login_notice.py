import queue

from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass.core.manager import PasswordManager


class _DummyConfigManager:
    def __init__(self, cfg: dict) -> None:
        self.cfg = dict(cfg)
        self.saved: list[dict] = []

    def load_config(self) -> dict:
        return dict(self.cfg)

    def save_config(self, cfg: dict) -> None:
        snapshot = dict(cfg)
        self.cfg = snapshot
        self.saved.append(snapshot)


class _DummyNostrClient:
    def __init__(self, **kwargs) -> None:
        self.kwargs = kwargs
        self.current_manifest_id = None
        self.current_manifest = None


def _make_pm(cfg: dict) -> PasswordManager:
    pm = PasswordManager.__new__(PasswordManager)
    pm.config_manager = _DummyConfigManager(cfg)
    pm.state_manager = None
    pm.encryption_manager = object()
    pm.current_fingerprint = "fp-test"
    pm.parent_seed = "seed"
    pm.KEY_INDEX = b"index-key"
    pm.notifications = queue.Queue()
    pm._current_notification = None
    pm._notification_expiry = 0.0
    return pm


def test_first_online_login_emits_notice_and_persists_seen(monkeypatch):
    pm = _make_pm({"offline_mode": False, "relays": ["wss://relay.example"]})
    monkeypatch.setattr("seedpass.core.manager.NostrClient", _DummyNostrClient)
    monkeypatch.setattr("builtins.print", lambda *a, **k: None)

    pm._initialize_nostr_client()

    note = pm.get_current_notification()
    assert note is not None
    assert "ONLINE by default" in note.message
    assert pm.config_manager.cfg.get("online_mode_notice_seen") is True
    assert len(pm.config_manager.saved) == 1


def test_online_notice_not_repeated_when_seen(monkeypatch):
    pm = _make_pm(
        {
            "offline_mode": False,
            "online_mode_notice_seen": True,
            "relays": ["wss://relay.example"],
        }
    )
    monkeypatch.setattr("seedpass.core.manager.NostrClient", _DummyNostrClient)
    monkeypatch.setattr("builtins.print", lambda *a, **k: None)

    pm._initialize_nostr_client()

    assert pm.get_current_notification() is None
    assert pm.config_manager.saved == []
