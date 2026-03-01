from __future__ import annotations

import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from constants import APP_DIR

APPROVAL_STORE_VERSION = 1
VALID_APPROVAL_ACTIONS = {
    "export",
    "reveal_parent_seed",
    "private_key_retrieval",
}


def _store_path() -> Path:
    return APP_DIR / "agent_approvals.json"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(value: str) -> datetime:
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _load_store() -> dict[str, Any]:
    path = _store_path()
    if not path.exists():
        return {"version": APPROVAL_STORE_VERSION, "approvals": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"version": APPROVAL_STORE_VERSION, "approvals": []}
    if not isinstance(data, dict) or not isinstance(data.get("approvals"), list):
        return {"version": APPROVAL_STORE_VERSION, "approvals": []}
    return data


def _save_store(store: dict[str, Any]) -> None:
    path = _store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store, indent=2), encoding="utf-8")
    os.chmod(path, 0o600)


def issue_approval(
    *,
    action: str,
    ttl_seconds: int,
    uses: int,
    resource: str = "*",
    issued_by: str = "manual",
) -> dict[str, Any]:
    store = _load_store()
    now = _utcnow()
    approval_id = secrets.token_urlsafe(18)
    rec = {
        "id": approval_id,
        "action": action,
        "resource": resource,
        "issued_by": issued_by,
        "created_at_utc": now.isoformat(),
        "expires_at_utc": (now + timedelta(seconds=ttl_seconds)).isoformat(),
        "uses_remaining": int(uses),
        "revoked_at_utc": None,
    }
    store["approvals"].append(rec)
    _save_store(store)
    return rec


def approval_required(policy: dict[str, Any], action: str) -> bool:
    approvals_cfg = policy.get("approvals", {})
    if not isinstance(approvals_cfg, dict):
        return False
    required = approvals_cfg.get("require_for", [])
    if not isinstance(required, list):
        return False
    action_l = action.strip().lower()
    return any(str(v).strip().lower() == action_l for v in required)


def list_approvals(*, include_revoked: bool = False) -> list[dict[str, Any]]:
    approvals = _load_store().get("approvals", [])
    if include_revoked:
        return approvals
    return [a for a in approvals if not a.get("revoked_at_utc")]


def revoke_approval(approval_id: str) -> bool:
    store = _load_store()
    now = _utcnow().isoformat()
    changed = False
    for rec in store.get("approvals", []):
        if rec.get("id") == approval_id and not rec.get("revoked_at_utc"):
            rec["revoked_at_utc"] = now
            changed = True
            break
    if changed:
        _save_store(store)
    return changed


def consume_approval(
    *,
    approval_id: str,
    action: str,
    resource: str = "*",
) -> tuple[bool, str]:
    store = _load_store()
    now = _utcnow()
    for rec in store.get("approvals", []):
        if rec.get("id") != approval_id:
            continue
        if rec.get("revoked_at_utc"):
            return False, "approval_revoked"
        if str(rec.get("action", "")).lower() != action.lower():
            return False, "approval_action_mismatch"
        rec_resource = str(rec.get("resource", "*"))
        if rec_resource not in {"*", resource}:
            return False, "approval_resource_mismatch"
        expires = rec.get("expires_at_utc")
        if not expires or _parse_iso(expires) <= now:
            return False, "approval_expired"
        uses = int(rec.get("uses_remaining", 0))
        if uses <= 0:
            return False, "approval_exhausted"
        rec["uses_remaining"] = uses - 1
        _save_store(store)
        return True, "approval_consumed"
    return False, "approval_not_found"
