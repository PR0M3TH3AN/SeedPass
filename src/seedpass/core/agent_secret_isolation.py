from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from constants import APP_DIR
from utils.file_lock import exclusive_lock

ISOLATION_STORE_VERSION = 1
PARTITION_ENVELOPE_VERSION = 1
PARTITION_KDF_ITERATIONS = 200_000


def _factor_hash_path() -> Path:
    return APP_DIR / "agent_high_risk_factor.hash"


def _partition_envelope_path() -> Path:
    return APP_DIR / "agent_high_risk_partition.key.enc.json"


def _session_store_path() -> Path:
    return APP_DIR / "agent_high_risk_unlock.json"


def _session_lock_path() -> Path:
    return APP_DIR / "agent_high_risk_unlock.lock"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(value: str) -> datetime:
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _empty_store() -> dict[str, Any]:
    return {"version": ISOLATION_STORE_VERSION, "sessions": []}


def _load_session_store_unlocked() -> dict[str, Any]:
    path = _session_store_path()
    if not path.exists():
        return _empty_store()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return _empty_store()
    if not isinstance(data, dict) or not isinstance(data.get("sessions"), list):
        return _empty_store()
    return data


def _save_session_store_unlocked(store: dict[str, Any]) -> None:
    path = _session_store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store, indent=2), encoding="utf-8")
    os.chmod(path, 0o600)


def _factor_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _partition_key_tag(partition_key: str) -> str:
    return hashlib.sha256(partition_key.encode("utf-8")).hexdigest()


def _derive_wrapping_key(factor: str, salt: bytes, iterations: int) -> bytes:
    raw = hashlib.pbkdf2_hmac(
        "sha256",
        factor.encode("utf-8"),
        salt,
        int(iterations),
        dklen=32,
    )
    return base64.urlsafe_b64encode(raw)


def _build_envelope(partition_key: str, factor: str) -> dict[str, Any]:
    salt = os.urandom(16)
    key = _derive_wrapping_key(factor, salt, PARTITION_KDF_ITERATIONS)
    wrapped = Fernet(key).encrypt(partition_key.encode("utf-8")).decode("utf-8")
    return {
        "version": PARTITION_ENVELOPE_VERSION,
        "kdf": "pbkdf2-sha256",
        "iterations": PARTITION_KDF_ITERATIONS,
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "wrapped_partition_key": wrapped,
    }


def _load_partition_envelope() -> dict[str, Any] | None:
    path = _partition_envelope_path()
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    return data


def _unwrap_partition_key(envelope: dict[str, Any], factor: str) -> str:
    if int(envelope.get("version", 0)) != PARTITION_ENVELOPE_VERSION:
        raise ValueError("unsupported_partition_envelope_version")
    salt_b64 = str(envelope.get("salt_b64", ""))
    wrapped = str(envelope.get("wrapped_partition_key", ""))
    iterations = int(envelope.get("iterations", PARTITION_KDF_ITERATIONS))
    if not salt_b64 or not wrapped or iterations < 1:
        raise ValueError("invalid_partition_envelope")
    salt = base64.b64decode(salt_b64)
    key = _derive_wrapping_key(factor, salt, iterations)
    try:
        return Fernet(key).decrypt(wrapped.encode("utf-8")).decode("utf-8")
    except (InvalidToken, ValueError) as exc:
        raise ValueError("high_risk_factor_invalid") from exc


def set_high_risk_factor(factor: str) -> None:
    app_dir = _factor_hash_path().parent
    app_dir.mkdir(parents=True, exist_ok=True)

    # Keep legacy hash marker for compatibility while enforcing envelope unwrap.
    hash_path = _factor_hash_path()
    hash_path.write_text(_factor_hash(factor), encoding="utf-8")
    os.chmod(hash_path, 0o600)

    partition_key = Fernet.generate_key().decode("ascii")
    envelope = _build_envelope(partition_key, factor)
    envelope_path = _partition_envelope_path()
    envelope_path.write_text(json.dumps(envelope, indent=2), encoding="utf-8")
    os.chmod(envelope_path, 0o600)


def high_risk_factor_configured() -> bool:
    env_path = _partition_envelope_path()
    if env_path.exists():
        return True
    path = _factor_hash_path()
    return path.exists() and bool(path.read_text(encoding="utf-8").strip())


def verify_high_risk_factor(factor: str) -> bool:
    envelope = _load_partition_envelope()
    if envelope is not None:
        try:
            _unwrap_partition_key(envelope, factor)
            return True
        except ValueError:
            return False

    # Legacy fallback if envelope has not been initialized yet.
    path = _factor_hash_path()
    if not path.exists():
        return False
    expected = path.read_text(encoding="utf-8").strip()
    if not expected:
        return False
    return _factor_hash(factor) == expected


def unwrap_high_risk_partition_key(factor: str) -> str:
    envelope = _load_partition_envelope()
    if envelope is None:
        raise ValueError("high_risk_partition_not_configured")
    return _unwrap_partition_key(envelope, factor)


def grant_high_risk_unlock(
    *, fingerprint: str, ttl_seconds: int, partition_key_tag: str | None = None
) -> dict[str, Any]:
    now = _utcnow()
    rec = {
        "fingerprint": str(fingerprint),
        "created_at_utc": now.isoformat(),
        "expires_at_utc": (now + timedelta(seconds=int(ttl_seconds))).isoformat(),
        "partition_key_tag": str(partition_key_tag or ""),
    }
    with exclusive_lock(_session_lock_path()):
        store = _load_session_store_unlocked()
        sessions = [
            s
            for s in store.get("sessions", [])
            if str(s.get("fingerprint", "")) != str(fingerprint)
        ]
        sessions.append(rec)
        store["sessions"] = sessions
        _save_session_store_unlocked(store)
    return rec


def high_risk_unlocked(*, fingerprint: str) -> tuple[bool, str]:
    now = _utcnow()
    with exclusive_lock(_session_lock_path()):
        store = _load_session_store_unlocked()
        sessions = store.get("sessions", [])
        kept: list[dict[str, Any]] = []
        matched: dict[str, Any] | None = None
        for rec in sessions:
            expires = str(rec.get("expires_at_utc", ""))
            try:
                valid = bool(expires) and _parse_iso(expires) > now
            except Exception:
                valid = False
            if not valid:
                continue
            kept.append(rec)
            if str(rec.get("fingerprint", "")) == str(fingerprint):
                matched = rec
        if len(kept) != len(sessions):
            store["sessions"] = kept
            _save_session_store_unlocked(store)
        if matched:
            return True, str(matched.get("expires_at_utc", ""))
    return False, ""


def revoke_high_risk_unlock(*, fingerprint: str) -> bool:
    changed = False
    with exclusive_lock(_session_lock_path()):
        store = _load_session_store_unlocked()
        sessions = store.get("sessions", [])
        kept = [
            s for s in sessions if str(s.get("fingerprint", "")) != str(fingerprint)
        ]
        changed = len(kept) != len(sessions)
        if changed:
            store["sessions"] = kept
            _save_session_store_unlocked(store)
    return changed


def unlocked_partition_key_tag(*, fingerprint: str) -> str:
    now = _utcnow()
    with exclusive_lock(_session_lock_path()):
        store = _load_session_store_unlocked()
        sessions = store.get("sessions", [])
        for rec in sessions:
            if str(rec.get("fingerprint", "")) != str(fingerprint):
                continue
            expires = str(rec.get("expires_at_utc", ""))
            try:
                if not expires or _parse_iso(expires) <= now:
                    continue
            except Exception:
                continue
            return str(rec.get("partition_key_tag", ""))
    return ""


def partition_key_tag_for_factor(factor: str) -> str:
    partition_key = unwrap_high_risk_partition_key(factor)
    return _partition_key_tag(partition_key)
