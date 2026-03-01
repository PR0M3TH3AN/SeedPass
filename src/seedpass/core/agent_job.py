from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from constants import APP_DIR

JOB_STORE_VERSION = 1


def _store_path() -> Path:
    return APP_DIR / "agent_jobs.json"


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _empty_store() -> dict[str, Any]:
    return {"version": JOB_STORE_VERSION, "jobs": []}


def _load_store() -> dict[str, Any]:
    path = _store_path()
    if not path.exists():
        return _empty_store()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return _empty_store()
    if not isinstance(data, dict) or not isinstance(data.get("jobs"), list):
        return _empty_store()
    return data


def _save_store(store: dict[str, Any]) -> None:
    path = _store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store, indent=2), encoding="utf-8")
    os.chmod(path, 0o600)


def list_job_profiles(*, include_revoked: bool = False) -> list[dict[str, Any]]:
    jobs = _load_store().get("jobs", [])
    if include_revoked:
        return jobs
    return [v for v in jobs if not v.get("revoked_at_utc")]


def get_job_profile(job_id: str) -> dict[str, Any] | None:
    target = str(job_id).strip()
    if not target:
        return None
    for rec in _load_store().get("jobs", []):
        if str(rec.get("id", "")) == target:
            return rec
    return None


def create_job_profile(
    *,
    job_id: str,
    fingerprint: str,
    query: str,
    auth_broker: str,
    broker_service: str,
    broker_account: str,
    broker_command: str | None,
    policy_binding: str,
    policy_stamp: str,
    schedule: str,
    description: str,
    host_binding: str,
    lease_only: bool,
    lease_ttl: int,
    lease_uses: int,
    reveal: bool,
) -> dict[str, Any]:
    job_id = str(job_id).strip()
    if not job_id:
        raise ValueError("job_id_required")
    if get_job_profile(job_id):
        raise ValueError("job_exists")
    rec = {
        "id": job_id,
        "fingerprint": str(fingerprint).strip(),
        "query": str(query),
        "auth_broker": str(auth_broker).strip().lower(),
        "broker_service": str(broker_service).strip(),
        "broker_account": str(broker_account).strip(),
        "broker_command": str(broker_command or "").strip() or None,
        "policy_binding": str(policy_binding).strip() or "default",
        "policy_stamp": str(policy_stamp).strip(),
        "schedule": str(schedule).strip(),
        "description": str(description).strip(),
        "host_binding": str(host_binding).strip(),
        "lease_only": bool(lease_only),
        "lease_ttl": int(lease_ttl),
        "lease_uses": int(lease_uses),
        "reveal": bool(reveal),
        "created_at_utc": _utcnow_iso(),
        "revoked_at_utc": None,
    }
    store = _load_store()
    store.setdefault("version", JOB_STORE_VERSION)
    store.setdefault("jobs", [])
    store["jobs"].append(rec)
    _save_store(store)
    return rec


def revoke_job_profile(job_id: str) -> bool:
    job_id = str(job_id).strip()
    if not job_id:
        return False
    store = _load_store()
    changed = False
    now = _utcnow_iso()
    for rec in store.get("jobs", []):
        if str(rec.get("id", "")) == job_id and not rec.get("revoked_at_utc"):
            rec["revoked_at_utc"] = now
            changed = True
            break
    if changed:
        _save_store(store)
    return changed
