import logging
import queue

import seedpass.core.manager as manager_module


def _make_pm():
    pm = manager_module.PasswordManager.__new__(manager_module.PasswordManager)
    pm.offline_mode = False
    pm.notifications = queue.Queue()
    pm.error_queue = queue.Queue()
    pm.notify = lambda msg, level="INFO": pm.notifications.put(
        manager_module.Notification(msg, level)
    )
    pm.nostr_client = object()
    return pm


def test_start_background_sync_error(monkeypatch, caplog):
    pm = _make_pm()

    async def failing_sync(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(pm, "attempt_initial_sync_async", failing_sync)
    monkeypatch.setattr(pm, "sync_index_from_nostr_async", failing_sync)

    pm.start_background_sync()
    pm._sync_task.join(timeout=1)

    with caplog.at_level(logging.WARNING):
        pm.poll_background_errors()

    note = pm.notifications.get_nowait()
    assert "boom" in note.message
    assert "boom" in caplog.text


def test_start_background_relay_check_error(monkeypatch, caplog):
    pm = _make_pm()

    class DummyClient:
        def check_relay_health(self, *_args, **_kwargs):
            raise RuntimeError("relay boom")

    pm.nostr_client = DummyClient()

    pm.start_background_relay_check()
    pm._relay_thread.join(timeout=1)

    with caplog.at_level(logging.WARNING):
        pm.poll_background_errors()

    note = pm.notifications.get_nowait()
    assert "relay boom" in note.message
    assert "relay boom" in caplog.text
