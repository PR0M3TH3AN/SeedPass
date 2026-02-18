import sys
from pathlib import Path

from helpers import TEST_SEED
from seedpass.core.totp import TotpManager

sys.path.append(str(Path(__file__).resolve().parents[1]))


class FakeNostrClient:
    def __init__(self, *args, **kwargs):
        self.published = []

    def publish_snapshot(self, data: bytes):
        self.published.append(data)
        return None, "abcd"


def test_handle_display_totp_codes(monkeypatch, capsys, password_manager):
    pm = password_manager
    pm.nostr_client = FakeNostrClient()

    pm.entry_manager.add_totp("Example", TEST_SEED)

    monkeypatch.setattr(TotpManager, "current_code_from_secret", lambda *a, **k: "123456")
    monkeypatch.setattr(pm.entry_manager, "get_totp_time_remaining", lambda *a, **k: 30)

    # interrupt the loop after first iteration
    monkeypatch.setattr(
        "seedpass.core.manager.timed_input",
        lambda *a, **k: (_ for _ in ()).throw(KeyboardInterrupt()),
    )

    pm.handle_display_totp_codes()
    out = capsys.readouterr().out
    assert "Imported 2FA Codes" in out
    assert "[0] Example" in out
    assert "123456" in out


def test_display_totp_codes_excludes_archived(monkeypatch, capsys, password_manager):
    pm = password_manager
    pm.nostr_client = FakeNostrClient()

    pm.entry_manager.add_totp("Visible", TEST_SEED)
    pm.entry_manager.add_totp("Hidden", TEST_SEED)
    pm.entry_manager.modify_entry(1, archived=True)

    monkeypatch.setattr(TotpManager, "current_code_from_secret", lambda *a, **k: "123456")
    monkeypatch.setattr(pm.entry_manager, "get_totp_time_remaining", lambda *a, **k: 30)

    monkeypatch.setattr(
        "seedpass.core.manager.timed_input",
        lambda *a, **k: (_ for _ in ()).throw(KeyboardInterrupt()),
    )

    pm.handle_display_totp_codes()
    out = capsys.readouterr().out
    assert "Visible" in out
    assert "Hidden" not in out
