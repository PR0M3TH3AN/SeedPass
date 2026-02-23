import asyncio

from seedpass.core.manager import PasswordManager
from seedpass.core import manager as manager_module


def test_start_background_vault_sync_thread_worker_path(monkeypatch):
    pm = PasswordManager.__new__(PasswordManager)
    pm.offline_mode = False

    events = []

    async def fake_sync_vault_async(*, alt_summary=None):
        return {"alt_summary": alt_summary}

    monkeypatch.setattr(pm, "sync_vault_async", fake_sync_vault_async)
    monkeypatch.setattr(
        manager_module.bus, "publish", lambda *args: events.append(args)
    )

    class ImmediateThread:
        def __init__(self, target, daemon):
            self._target = target
            self.daemon = daemon

        def start(self):
            self._target()

    monkeypatch.setattr(manager_module.threading, "Thread", ImmediateThread)

    pm.start_background_vault_sync("thread-path")

    assert ("sync_started",) in events
    assert ("sync_finished", {"alt_summary": "thread-path"}) in events


def test_start_background_vault_sync_async_worker_path(monkeypatch):
    pm = PasswordManager.__new__(PasswordManager)
    pm.offline_mode = False

    events = []

    async def fake_sync_vault_async(*, alt_summary=None):
        return {"alt_summary": alt_summary}

    monkeypatch.setattr(pm, "sync_vault_async", fake_sync_vault_async)
    monkeypatch.setattr(
        manager_module.bus, "publish", lambda *args: events.append(args)
    )

    async def runner():
        pm.start_background_vault_sync("async-path")
        await asyncio.sleep(0.02)

    asyncio.run(runner())

    assert ("sync_started",) in events
    assert ("sync_finished", {"alt_summary": "async-path"}) in events
