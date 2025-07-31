import queue
from pathlib import Path
from types import SimpleNamespace
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from seedpass.core.manager import PasswordManager, EncryptionMode


def _make_pm() -> PasswordManager:
    pm = PasswordManager.__new__(PasswordManager)
    pm.encryption_mode = EncryptionMode.SEED_ONLY
    pm.vault = SimpleNamespace()
    pm.backup_manager = SimpleNamespace()
    pm.parent_seed = "seed"
    pm.profile_stack = []
    pm.current_fingerprint = None
    pm.sync_vault = lambda: None
    pm.notifications = queue.Queue()
    return pm


def test_import_non_backup_file(monkeypatch, capsys):
    pm = _make_pm()
    called = {"called": False}

    def fake_import(*_a, **_k):
        called["called"] = True

    monkeypatch.setattr("seedpass.core.manager.import_backup", fake_import)
    monkeypatch.setattr(
        "seedpass.core.manager.clear_header_with_notification", lambda *a, **k: None
    )

    pm.handle_import_database(Path("data.txt"))
    out = capsys.readouterr().out
    assert "json.enc" in out.lower()
    assert called["called"] is False


def test_import_missing_file(monkeypatch, capsys):
    pm = _make_pm()

    def raise_missing(*_a, **_k):
        raise FileNotFoundError

    monkeypatch.setattr("seedpass.core.manager.import_backup", raise_missing)
    monkeypatch.setattr(
        "seedpass.core.manager.clear_header_with_notification", lambda *a, **k: None
    )

    pm.handle_import_database(Path("missing.json.enc"))
    out = capsys.readouterr().out
    assert "not found" in out.lower()
