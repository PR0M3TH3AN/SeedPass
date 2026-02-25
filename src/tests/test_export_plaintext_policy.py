import queue
from pathlib import Path

from seedpass.core.manager import PasswordManager
import seedpass.core.manager as manager_module


def _make_pm(tmp_path: Path) -> PasswordManager:
    pm = PasswordManager.__new__(PasswordManager)
    pm.fingerprint_dir = tmp_path
    pm.current_fingerprint = "user123"
    pm.profile_stack = []
    pm.notifications = queue.Queue()
    pm.vault = object()
    pm.backup_manager = object()
    pm.notify = lambda *_a, **_k: None
    return pm


def test_plaintext_export_requires_second_confirmation(monkeypatch, tmp_path):
    pm = _make_pm(tmp_path)
    monkeypatch.setattr(
        manager_module, "clear_header_with_notification", lambda *a, **k: None
    )

    confirms = iter([True, False])
    monkeypatch.setattr(
        "seedpass.core.manager.confirm_action",
        lambda *_a, **_k: next(confirms),
    )
    called = {"count": 0}
    monkeypatch.setattr(
        manager_module,
        "export_backup",
        lambda *_a, **_k: called.__setitem__("count", called["count"] + 1),
    )

    result = pm.handle_export_database()
    assert result is None
    assert called["count"] == 0
