from __future__ import annotations

import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from constants import APP_DIR
from utils.file_lock import exclusive_lock

LEASE_STORE_VERSION = 1


def _store_path() -> Path:
    return APP_DIR / "agent_secret_leases.json"


def _lock_path() -> Path:
    return APP_DIR / "agent_secret_leases.lock"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(value: str) -> datetime:
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _empty_store() -> dict[str, Any]:
    return {"version": LEASE_STORE_VERSION, "leases": []}


def _load_store_unlocked() -> dict[str, Any]:
    path = _store_path()
    if not path.exists():
        return _empty_store()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return _empty_store()
    if not isinstance(data, dict) or not isinstance(data.get("leases"), list):
        return _empty_store()
    return data


def _save_store_unlocked(store: dict[str, Any]) -> None:
    path = _store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store, indent=2), encoding="utf-8")
    os.chmod(path, 0o600)


def issue_lease(
    *,
    fingerprint: str,
    index: int,
    kind: str,
    label: str,
    ttl_seconds: int,
    uses: int,
    token_id: str | None = None,
) -> dict[str, Any]:
    now = _utcnow()
    rec = {
        "id": secrets.token_urlsafe(18),
        "fingerprint": str(fingerprint),
        "resource": f"entry:{kind}:{index}",
        "index": int(index),
        "kind": str(kind),
        "label": str(label),
        "created_at_utc": now.isoformat(),
        "expires_at_utc": (now + timedelta(seconds=int(ttl_seconds))).isoformat(),
        "uses_remaining": int(uses),
        "token_id": token_id,
        "revoked_at_utc": None,
    }
    with exclusive_lock(_lock_path()):
        store = _load_store_unlocked()
        store.setdefault("version", LEASE_STORE_VERSION)
        store.setdefault("leases", [])
        store["leases"].append(rec)
        _save_store_unlocked(store)
    return rec


def list_leases(*, include_revoked: bool = False) -> list[dict[str, Any]]:
    with exclusive_lock(_lock_path()):
        leases = _load_store_unlocked().get("leases", [])
    if include_revoked:
        return leases
    return [v for v in leases if not v.get("revoked_at_utc")]


def revoke_lease(lease_id: str) -> bool:
    changed = False
    with exclusive_lock(_lock_path()):
        store = _load_store_unlocked()
        for rec in store.get("leases", []):
            if rec.get("id") == lease_id and not rec.get("revoked_at_utc"):
                rec["revoked_at_utc"] = _utcnow().isoformat()
                changed = True
                break
        if changed:
            _save_store_unlocked(store)
    return changed


def consume_lease(
    *,
    lease_id: str,
    fingerprint: str | None = None,
) -> tuple[bool, str, dict[str, Any] | None]:
    with exclusive_lock(_lock_path()):
        store = _load_store_unlocked()
        now = _utcnow()
        for rec in store.get("leases", []):
            if rec.get("id") != lease_id:
                continue
            if rec.get("revoked_at_utc"):
                return False, "lease_revoked", None
            if fingerprint and str(rec.get("fingerprint")) != str(fingerprint):
                return False, "lease_fingerprint_mismatch", None
            expires = str(rec.get("expires_at_utc", ""))
            if not expires or _parse_iso(expires) <= now:
                return False, "lease_expired", None
            uses = int(rec.get("uses_remaining", 0))
            if uses <= 0:
                return False, "lease_exhausted", None
            rec["uses_remaining"] = uses - 1
            _save_store_unlocked(store)
            return True, "lease_consumed", dict(rec)
    return False, "lease_not_found", None
