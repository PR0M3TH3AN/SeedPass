import json
import hashlib
import hmac
import queue
from pathlib import Path
from types import SimpleNamespace

import importlib
import pytest

from seedpass.core.manager import PasswordManager, AuditLogger
import seedpass.core.manager as manager_module


def test_audit_logger_records_events(monkeypatch, tmp_path):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    pm = PasswordManager.__new__(PasswordManager)
    pm.fingerprint_dir = tmp_path
    pm.current_fingerprint = "user123"
    pm.profile_stack = []
    pm.setup_encryption_manager = lambda *a, **k: None
    pm.initialize_bip85 = lambda: None
    pm.initialize_managers = lambda: None
    pm.update_activity = lambda: None
    pm.verify_password = lambda pw: True
    pm.notifications = queue.Queue()
    pm.parent_seed = "seed phrase"
    pm.config_manager = SimpleNamespace(get_quick_unlock=lambda: True)

    manager_module.clear_header_with_notification = lambda *a, **k: None

    pm.unlock_vault(password="pw")

    dest = tmp_path / "db.json.enc"
    monkeypatch.setattr(manager_module, "export_backup", lambda *a, **k: dest)
    pm.vault = object()
    pm.backup_manager = object()
    monkeypatch.setattr("seedpass.core.manager.confirm_action", lambda *_a, **_k: True)
    pm.handle_export_database(dest)

    confirms = iter([True, False])
    monkeypatch.setattr(
        "seedpass.core.manager.confirm_action", lambda *_a, **_k: next(confirms)
    )
    pm.encryption_manager = SimpleNamespace(encrypt_and_save_file=lambda *a, **k: None)
    pm.handle_backup_reveal_parent_seed(password="pw")

    log_path = tmp_path / ".seedpass" / "audit.log"
    lines = [json.loads(l) for l in log_path.read_text().splitlines()]
    events = [e["event"] for e in lines]
    assert "quick_unlock" in events
    assert "backup_export" in events
    assert "seed_reveal" in events


def _verify_chain(path: Path, key: bytes) -> bool:
    prev = "0" * 64
    for line in path.read_text().splitlines():
        data = json.loads(line)
        sig = data.pop("sig")
        payload = json.dumps(data, sort_keys=True, separators=(",", ":"))
        expected = hmac.new(
            key, f"{prev}{payload}".encode(), hashlib.sha256
        ).hexdigest()
        if sig != expected:
            return False
        prev = sig
    return True


def test_audit_log_tamper_evident(monkeypatch, tmp_path):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    key = hashlib.sha256(b"seed").digest()
    logger = AuditLogger(key)
    logger.log("one", {})
    logger.log("two", {})
    log_path = tmp_path / ".seedpass" / "audit.log"
    assert _verify_chain(log_path, key)
    lines = log_path.read_text().splitlines()
    tampered = json.loads(lines[0])
    tampered["event"] = "evil"
    lines[0] = json.dumps(tampered)
    log_path.write_text("\n".join(lines) + "\n")
    assert not _verify_chain(log_path, key)
