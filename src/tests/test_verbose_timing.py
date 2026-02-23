import asyncio
import logging

from seedpass.core.manager import PasswordManager


def test_unlock_vault_logs_time(monkeypatch, caplog, tmp_path):
    pm = PasswordManager.__new__(PasswordManager)
    pm.fingerprint_dir = tmp_path
    pm.setup_encryption_manager = lambda path, pw=None: None
    pm.initialize_bip85 = lambda: None
    pm.initialize_managers = lambda: None
    pm.update_activity = lambda: None
    pm.verbose_timing = True
    caplog.set_level(logging.INFO, logger="seedpass.core.manager")
    times = iter([0.0, 1.0])
    monkeypatch.setattr("seedpass.core.manager.time.perf_counter", lambda: next(times))
    pm.unlock_vault("pw")
    assert "Vault unlocked in 1.00 seconds" in caplog.text


def test_publish_snapshot_logs_time(dummy_nostr_client, monkeypatch, caplog):
    client, _relay = dummy_nostr_client
    client.verbose_timing = True
    caplog.set_level(logging.INFO, logger="nostr.client")
    times = iter([0.0, 1.0])
    monkeypatch.setattr("nostr.client.time.perf_counter", lambda: next(times))
    asyncio.run(client.publish_snapshot(b"data"))
    assert "publish_snapshot completed in 1.00 seconds" in caplog.text
