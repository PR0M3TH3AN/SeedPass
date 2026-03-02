from __future__ import annotations

import asyncio
from types import SimpleNamespace

from seedpass.core.manager import PasswordManager


def test_sync_vault_async_sets_last_error_when_no_encrypted_data() -> None:
    pm = PasswordManager.__new__(PasswordManager)
    pm.offline_mode = False
    pm.get_encrypted_data = lambda: b""
    pm.nostr_client = SimpleNamespace(last_error=None)

    result = asyncio.run(pm.sync_vault_async())

    assert result is None
    assert pm.nostr_client.last_error == "No encrypted index data available to sync."


def test_sync_vault_async_preserves_existing_error_when_publish_returns_none() -> None:
    pm = PasswordManager.__new__(PasswordManager)
    pm.offline_mode = False
    pm.is_dirty = True
    pm.get_encrypted_data = lambda: b"encrypted"
    pm.state_manager = None
    client = SimpleNamespace(last_error=None, get_delta_events=lambda: [])

    def _publish_snapshot(_enc):
        client.last_error = "relay timeout"
        return None, None

    client.publish_snapshot = _publish_snapshot
    pm.nostr_client = client

    result = asyncio.run(pm.sync_vault_async())

    assert result is None
    assert pm.nostr_client.last_error == "relay timeout"
    assert pm.is_dirty is False


def test_sync_vault_async_sets_default_error_when_publish_returns_none() -> None:
    pm = PasswordManager.__new__(PasswordManager)
    pm.offline_mode = False
    pm.is_dirty = True
    pm.get_encrypted_data = lambda: b"encrypted"
    pm.state_manager = None
    pm.nostr_client = SimpleNamespace(
        last_error=None,
        publish_snapshot=lambda _enc: (None, None),
        get_delta_events=lambda: [],
    )

    result = asyncio.run(pm.sync_vault_async())

    assert result is None
    assert pm.nostr_client.last_error == (
        "Failed to publish encrypted index to configured relays."
    )
    assert pm.is_dirty is False


def test_sync_index_from_nostr_async_notifies_last_error_when_snapshot_missing() -> None:
    notifications: list[tuple[str, str]] = []

    async def _no_snapshot():
        return None

    pm = PasswordManager.__new__(PasswordManager)
    pm.current_fingerprint = "fp"
    pm.nostr_client = SimpleNamespace(
        relays=["wss://relay-1"],
        last_error="timeout waiting for snapshot",
        fetch_latest_snapshot=_no_snapshot,
    )
    pm.notify = lambda msg, level="INFO": notifications.append((msg, level))

    asyncio.run(pm.sync_index_from_nostr_async())

    assert notifications == [
        ("Sync failed: timeout waiting for snapshot", "WARNING"),
    ]


def test_sync_index_from_nostr_async_notifies_exception_when_fetch_raises() -> None:
    notifications: list[tuple[str, str]] = []

    async def _boom():
        raise RuntimeError("relay unreachable")

    pm = PasswordManager.__new__(PasswordManager)
    pm.current_fingerprint = "fp"
    pm.nostr_client = SimpleNamespace(
        relays=["wss://relay-1"],
        last_error=None,
        fetch_latest_snapshot=_boom,
    )
    pm.notify = lambda msg, level="INFO": notifications.append((msg, level))

    asyncio.run(pm.sync_index_from_nostr_async())

    assert notifications == [
        ("Sync failed: relay unreachable", "WARNING"),
    ]
