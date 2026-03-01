"""SeedPass FastAPI server."""

from __future__ import annotations

import os
import tempfile
import json
from datetime import datetime, timezone
from pathlib import Path
import secrets
import queue
import time
import socket
import shlex
from collections import defaultdict, deque
from typing import Any, List, Optional
import hashlib
import hmac

import logging

from fastapi import FastAPI, Header, HTTPException, Request, Response
import asyncio
import sys

import bcrypt
from constants import APP_DIR

from seedpass.core.manager import PasswordManager
from seedpass.core.entry_types import EntryType
from seedpass.core.agent_export_policy import (
    allowed_kinds,
    build_policy_filtered_export_package,
    compute_policy_stamp,
    evaluate_full_export,
    evaluate_kind_export,
    load_export_policy,
    record_export_policy_event,
    verify_filtered_export_package,
)
from seedpass.core.agent_approval import approval_required, consume_approval
from seedpass.core.agent_secret_isolation import (
    grant_high_risk_unlock,
    high_risk_factor_configured,
    high_risk_unlocked,
    partition_key_tag_for_factor,
    revoke_high_risk_unlock,
    unlocked_partition_key_tag,
    verify_high_risk_factor,
)
from seedpass.core.agent_secret_lease import issue_lease
from seedpass.core.agent_job import (
    create_job_profile,
    get_job_profile,
    list_job_profiles,
    revoke_job_profile,
)
from seedpass.core.agent_recovery import (
    list_recovery_drills,
    record_recovery_drill,
    recover_secret,
    split_secret,
    verify_recovery_drills,
)
from seedpass.core.high_risk_partition_store import load_partition_entry
from seedpass.core.api import UtilityService

_RATE_LIMIT = int(os.getenv("SEEDPASS_RATE_LIMIT", "100"))
_RATE_WINDOW = int(os.getenv("SEEDPASS_RATE_WINDOW", "60"))
_RATE_LIMIT_STR = f"{_RATE_LIMIT}/{_RATE_WINDOW} seconds"
_MAX_IMPORT_BYTES = int(os.getenv("SEEDPASS_MAX_IMPORT_BYTES", str(10 * 1024 * 1024)))
_UNLOCK_ATTEMPT_LIMIT = int(os.getenv("SEEDPASS_UNLOCK_ATTEMPT_LIMIT", "5"))
_UNLOCK_ATTEMPT_WINDOW = int(os.getenv("SEEDPASS_UNLOCK_ATTEMPT_WINDOW", "300"))

app = FastAPI()

logger = logging.getLogger(__name__)
_SENSITIVE_CONFIG_KEYS = {"password_hash", "pin_hash"}


@app.middleware("http")
async def dynamic_cors_headers(request: Request, call_next):
    response = await call_next(request)
    origins = {
        o.strip()
        for o in os.getenv("SEEDPASS_CORS_ORIGINS", "").split(",")
        if o.strip()
    }
    request_origin = request.headers.get("origin")
    if request_origin and request_origin in origins:
        response.headers["access-control-allow-origin"] = request_origin
        response.headers["vary"] = "Origin"
    return response


def _get_pm(request: Request) -> PasswordManager:
    pm = getattr(request.app.state, "pm", None)
    if pm is None:
        raise HTTPException(status_code=503, detail="Server not initialized")
    return pm


def _check_token(request: Request, auth: str | None) -> None:
    if auth is None or not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")
    raw_token = auth.split(" ", 1)[1]
    token = raw_token.encode()
    token_hash = getattr(request.app.state, "token_hash", b"")
    if not token_hash or not bcrypt.checkpw(token, token_hash):
        raise HTTPException(status_code=401, detail="Unauthorized")
    _enforce_rate_limit(request, raw_token)


def _enforce_rate_limit(request: Request, raw_token: str) -> None:
    now = time.monotonic()
    key = _request_rate_key(request, raw_token)
    buckets = getattr(request.app.state, "rate_limit_buckets", None)
    if buckets is None:
        buckets = defaultdict(deque)
        request.app.state.rate_limit_buckets = buckets
    bucket = buckets[key]
    while bucket and (now - bucket[0]) > _RATE_WINDOW:
        bucket.popleft()
    if len(bucket) >= _RATE_LIMIT:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded ({_RATE_LIMIT_STR})",
        )
    bucket.append(now)


def _request_rate_key(request: Request, raw_token: str) -> str:
    client = request.client.host if request.client else "unknown"
    token_tag = hashlib.blake2s(raw_token.encode("utf-8"), digest_size=8).hexdigest()
    return f"{client}:{token_tag}"


def _enforce_unlock_attempt_limit(request: Request, raw_token: str) -> None:
    """Enforce a stricter rate limit for repeated unlock attempts."""
    now = time.monotonic()
    key = _request_rate_key(request, raw_token)
    buckets = getattr(request.app.state, "unlock_attempt_buckets", None)
    if buckets is None:
        buckets = defaultdict(deque)
        request.app.state.unlock_attempt_buckets = buckets
    bucket = buckets[key]
    while bucket and (now - bucket[0]) > _UNLOCK_ATTEMPT_WINDOW:
        bucket.popleft()
    if len(bucket) >= _UNLOCK_ATTEMPT_LIMIT:
        raise HTTPException(
            status_code=429,
            detail=(
                "Too many failed unlock attempts. " "Try again after cooldown period."
            ),
        )


def _record_unlock_failure(request: Request, raw_token: str) -> None:
    now = time.monotonic()
    key = _request_rate_key(request, raw_token)
    buckets = getattr(request.app.state, "unlock_attempt_buckets", None)
    if buckets is None:
        buckets = defaultdict(deque)
        request.app.state.unlock_attempt_buckets = buckets
    buckets[key].append(now)


def _reload_relays(request: Request, relays: list[str]) -> None:
    """Reload the Nostr client with a new relay list."""
    pm = _get_pm(request)
    try:
        pm.nostr_client.close_client_pool()
    except (OSError, RuntimeError, ValueError) as exc:
        logger.warning("Failed to close NostrClient pool: %s", exc)
    try:
        pm.nostr_client.relays = relays
        pm.nostr_client.initialize_client_pool()
    except (OSError, RuntimeError, ValueError) as exc:
        logger.error("Failed to initialize NostrClient with relays %s: %s", relays, exc)


def start_server(
    fingerprint: str | None = None, unlock_password: str | None = None
) -> str:
    """Initialize global state and return a random API token.

    Parameters
    ----------
    fingerprint:
        Optional seed profile fingerprint to select before starting the server.
    unlock_password:
        Optional master password used to unlock vault during startup.
    """
    if fingerprint is None:
        pm = PasswordManager()
    else:
        pm = PasswordManager(fingerprint=fingerprint)
    if unlock_password is not None:
        pm.unlock_vault(unlock_password)
    app.state.pm = pm
    raw_token = secrets.token_urlsafe(32)
    app.state.token_hash = bcrypt.hashpw(raw_token.encode(), bcrypt.gensalt())
    app.state.rate_limit_buckets = defaultdict(deque)
    app.state.unlock_attempt_buckets = defaultdict(deque)
    return raw_token


def _require_password(request: Request, password: str | None) -> None:
    pm = _get_pm(request)
    if password is None or not pm.verify_password(password):
        raise HTTPException(status_code=401, detail="Invalid password")


def _require_unlocked(request: Request) -> None:
    """Ensure the active vault is unlocked before accessing protected routes."""
    pm = _get_pm(request)
    if bool(getattr(pm, "is_locked", False) or getattr(pm, "locked", False)):
        raise HTTPException(status_code=423, detail="Vault is locked")


def _validate_encryption_path(request: Request, path: Path) -> Path:
    """Validate and normalize ``path`` within the active fingerprint directory.

    Returns the resolved absolute path if validation succeeds.
    """

    pm = _get_pm(request)
    try:
        return pm.encryption_manager.resolve_relative_path(path)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


def _header_truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _active_fingerprint(pm: PasswordManager) -> str:
    return str(
        getattr(pm, "current_fingerprint", None)
        or getattr(pm, "fingerprint", None)
        or "default"
    )


def _policy_isolation_kinds(policy: dict[str, Any]) -> set[str]:
    cfg = policy.get("secret_isolation", {})
    if not isinstance(cfg, dict) or not bool(cfg.get("enabled", True)):
        return set()
    kinds = cfg.get("high_risk_kinds", [])
    if not isinstance(kinds, list):
        return set()
    return {str(v).strip().lower() for v in kinds if str(v).strip()}


def _require_high_risk_session(
    pm: PasswordManager, policy: dict[str, Any], required_kinds: set[str]
) -> None:
    isolation_kinds = _policy_isolation_kinds(policy)
    if not isolation_kinds or not required_kinds.intersection(isolation_kinds):
        return
    if not high_risk_factor_configured():
        return
    fp = _active_fingerprint(pm)
    unlocked, _expires_at = high_risk_unlocked(fingerprint=fp)
    if not unlocked:
        raise HTTPException(status_code=403, detail="policy_deny:high_risk_locked")


def _hydrate_partitioned_entry_if_needed(
    pm: PasswordManager, entry_id: int, entry: dict[str, Any]
) -> dict[str, Any]:
    if str(entry.get("partition", "")).strip().lower() != "high_risk":
        return entry
    fp = _active_fingerprint(pm)
    tag = unlocked_partition_key_tag(fingerprint=fp)
    if not tag:
        raise HTTPException(status_code=403, detail="policy_deny:high_risk_locked")
    try:
        loaded = load_partition_entry(Path(pm.fingerprint_dir), tag, int(entry_id))
    except ValueError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    if not isinstance(loaded, dict):
        raise HTTPException(status_code=404, detail="high_risk_partition_entry_missing")
    return loaded


def _job_profile_command(*, fingerprint: str, job_id: str) -> str:
    fp = shlex.quote(str(fingerprint))
    jid = shlex.quote(str(job_id))
    return f"seedpass --fingerprint {fp} agent job-profile-run {jid}"


def _cron_template(*, schedule: str, command: str) -> str:
    return f"{schedule} {command} >> /var/log/seedpass-agent-job.log 2>&1"


def _systemd_templates(
    *, unit_name: str, schedule: str, command: str
) -> tuple[str, str]:
    service = "\n".join(
        [
            "[Unit]",
            f"Description=SeedPass agent job ({unit_name})",
            "",
            "[Service]",
            "Type=oneshot",
            f"ExecStart={command}",
        ]
    )
    timer = "\n".join(
        [
            "[Unit]",
            f"Description=SeedPass agent timer ({unit_name})",
            "",
            "[Timer]",
            f"OnCalendar={schedule}",
            "Persistent=true",
            "",
            "[Install]",
            "WantedBy=timers.target",
        ]
    )
    return service, timer


def _template_key_path() -> Path:
    return APP_DIR / "agent_template_signing.key"


def _load_template_signing_key() -> bytes:
    path = _template_key_path()
    if path.exists():
        return path.read_bytes()
    path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    path.write_bytes(key)
    os.chmod(path, 0o600)
    return key


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _template_content(payload: dict[str, Any]) -> dict[str, Any]:
    content: dict[str, Any] = {
        "mode": payload.get("mode"),
        "schedule": payload.get("schedule"),
        "command": payload.get("command"),
    }
    if "cron_line" in payload:
        content["cron_line"] = payload.get("cron_line")
    if "systemd_service" in payload:
        content["systemd_service"] = payload.get("systemd_service")
    if "systemd_timer" in payload:
        content["systemd_timer"] = payload.get("systemd_timer")
    if "unit_name" in payload:
        content["unit_name"] = payload.get("unit_name")
    return content


def _template_manifest(payload: dict[str, Any]) -> dict[str, Any]:
    content = _template_content(payload)
    template_hash = hashlib.sha256(_canonical_json(content).encode("utf-8")).hexdigest()
    policy_stamp = str(payload.get("policy_stamp", "") or "")
    host_binding = str(payload.get("host_binding", "") or "")
    job_profile_id = str(payload.get("job_profile_id", "") or "")
    msg = f"{template_hash}:{policy_stamp}:{host_binding}:{job_profile_id}".encode(
        "utf-8"
    )
    sig = hmac.new(_load_template_signing_key(), msg, hashlib.sha256).hexdigest()
    return {
        "schema_version": 1,
        "template_hash_sha256": template_hash,
        "policy_stamp": policy_stamp,
        "host_binding": host_binding,
        "job_profile_id": job_profile_id,
        "signature_hmac_sha256": sig,
    }


def _build_job_profile_template_payload(
    *,
    profile: dict[str, Any],
    job_id: str,
    mode: str,
    schedule: str | None,
    unit_name: str,
    include_manifest: bool,
) -> dict[str, Any]:
    mode_value = str(mode).strip().lower()
    if mode_value not in {"cron", "systemd"}:
        raise HTTPException(status_code=400, detail="invalid_mode")
    profile_schedule = str(profile.get("schedule", "")).strip()
    if schedule and str(schedule).strip():
        effective_schedule = str(schedule).strip()
        schedule_source = "provided"
    elif profile_schedule:
        effective_schedule = profile_schedule
        schedule_source = "profile"
    elif mode_value == "cron":
        effective_schedule = "*/15 * * * *"
        schedule_source = "default"
    else:
        effective_schedule = "*:0/15"
        schedule_source = "default"
    command = _job_profile_command(
        fingerprint=str(profile.get("fingerprint", "")).strip(),
        job_id=job_id,
    )
    payload: dict[str, Any] = {
        "status": "ok",
        "job_profile_id": job_id,
        "mode": mode_value,
        "schedule": effective_schedule,
        "schedule_source": schedule_source,
        "command": command,
        "policy_stamp": str(profile.get("policy_stamp", "")).strip() or None,
        "host_binding": str(profile.get("host_binding", "")).strip() or None,
    }
    if mode_value == "cron":
        payload["cron_line"] = _cron_template(
            schedule=effective_schedule, command=command
        )
    else:
        unit = str(unit_name).strip() or "seedpass-agent-job"
        service, timer = _systemd_templates(
            unit_name=unit,
            schedule=effective_schedule,
            command=command,
        )
        payload["unit_name"] = unit
        payload["systemd_service"] = service
        payload["systemd_timer"] = timer
    if include_manifest:
        payload["template_manifest"] = _template_manifest(payload)
    return payload


def _mask_value(value: str) -> str:
    if len(value) <= 4:
        return "*" * len(value)
    return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"


@app.get("/api/v1/entry")
async def search_entry(
    request: Request, query: str, authorization: str | None = Header(None)
) -> List[Any]:
    _check_token(request, authorization)
    _require_unlocked(request)
    pm = _get_pm(request)
    results = pm.entry_manager.search_entries(query)
    return [
        {
            "id": idx,
            "label": label,
            "username": username,
            "url": url,
            "archived": archived,
            "type": etype.value,
        }
        for idx, label, username, url, archived, etype in results
    ]


@app.get("/api/v1/high-risk/status")
def high_risk_status(
    request: Request, authorization: str | None = Header(None)
) -> dict[str, Any]:
    _check_token(request, authorization)
    pm = _get_pm(request)
    fp = _active_fingerprint(pm)
    unlocked, expires_at = high_risk_unlocked(fingerprint=fp)
    return {
        "status": "ok",
        "fingerprint": fp,
        "factor_configured": bool(high_risk_factor_configured()),
        "unlocked": bool(unlocked),
        "expires_at_utc": expires_at or None,
    }


@app.post("/api/v1/high-risk/unlock")
def high_risk_unlock(
    request: Request,
    data: dict[str, Any],
    authorization: str | None = Header(None),
    password: str | None = Header(None, alias="X-SeedPass-Password"),
    factor: str | None = Header(None, alias="X-SeedPass-High-Risk-Factor"),
) -> dict[str, Any]:
    _check_token(request, authorization)
    _require_password(request, password)
    _require_unlocked(request)
    pm = _get_pm(request)
    if not high_risk_factor_configured():
        raise HTTPException(status_code=400, detail="high_risk_factor_not_configured")
    if factor is None or not verify_high_risk_factor(factor):
        raise HTTPException(status_code=401, detail="high_risk_factor_invalid")
    try:
        key_tag = partition_key_tag_for_factor(factor)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc))
    policy = load_export_policy()
    ttl_default = int((policy.get("secret_isolation") or {}).get("unlock_ttl_sec", 300))
    ttl = int(data.get("ttl", ttl_default))
    if ttl < 1:
        raise HTTPException(status_code=400, detail="invalid_ttl")
    session = grant_high_risk_unlock(
        fingerprint=_active_fingerprint(pm), ttl_seconds=ttl, partition_key_tag=key_tag
    )
    cfg = getattr(pm, "config_manager", None)
    if cfg is not None and hasattr(cfg, "set_partition_unlock_state"):
        try:
            cfg.set_partition_unlock_state("high_risk", True)
        except Exception:
            pass
    return {
        "status": "ok",
        "fingerprint": _active_fingerprint(pm),
        "expires_at_utc": session.get("expires_at_utc"),
    }


@app.post("/api/v1/high-risk/lock")
def high_risk_lock(
    request: Request, authorization: str | None = Header(None)
) -> dict[str, Any]:
    _check_token(request, authorization)
    pm = _get_pm(request)
    fp = _active_fingerprint(pm)
    changed = revoke_high_risk_unlock(fingerprint=fp)
    cfg = getattr(pm, "config_manager", None)
    if cfg is not None and hasattr(cfg, "set_partition_unlock_state"):
        try:
            cfg.set_partition_unlock_state("high_risk", False)
        except Exception:
            pass
    return {"status": "ok", "fingerprint": fp, "locked": bool(changed)}


@app.get("/api/v1/agent/job-profiles")
def list_agent_job_profiles(
    request: Request,
    authorization: str | None = Header(None),
    show_revoked: bool = False,
) -> dict[str, Any]:
    _check_token(request, authorization)
    _require_unlocked(request)
    jobs = list_job_profiles(include_revoked=bool(show_revoked))
    return {"status": "ok", "job_profiles": jobs}


@app.post("/api/v1/agent/job-profiles")
def create_agent_job_profile(
    request: Request,
    data: dict[str, Any],
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    _check_token(request, authorization)
    _require_unlocked(request)
    pm = _get_pm(request)
    job_id = str(data.get("id", "")).strip()
    query = str(data.get("query", "")).strip()
    if not job_id or not query:
        raise HTTPException(status_code=400, detail="id_and_query_required")
    broker = str(data.get("auth_broker", "keyring")).strip().lower()
    if broker not in {"keyring", "command"}:
        raise HTTPException(status_code=400, detail="invalid_auth_broker")
    broker_command = str(data.get("broker_command", "")).strip() or None
    if broker == "command" and not broker_command:
        raise HTTPException(status_code=400, detail="broker_command_required")
    policy = load_export_policy()
    policy_stamp = compute_policy_stamp(policy)
    bind_host = str(data.get("bind_host", "current")).strip() or "current"
    if bind_host == "current":
        bind_host = socket.gethostname()
    fingerprint = str(data.get("fingerprint", "")).strip() or _active_fingerprint(pm)
    try:
        rec = create_job_profile(
            job_id=job_id,
            fingerprint=fingerprint,
            query=query,
            auth_broker=broker,
            broker_service=str(data.get("broker_service", "seedpass")).strip(),
            broker_account=str(data.get("broker_account", "")).strip() or fingerprint,
            broker_command=broker_command,
            policy_binding=str(data.get("policy_binding", "default")).strip(),
            policy_stamp=policy_stamp,
            schedule=str(data.get("schedule", "")).strip(),
            description=str(data.get("description", "")).strip(),
            host_binding=bind_host,
            lease_only=bool(data.get("lease_only", False)),
            lease_ttl=int(data.get("lease_ttl", 30)),
            lease_uses=int(data.get("lease_uses", 1)),
            reveal=bool(data.get("reveal", False)),
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return {"status": "ok", "job_profile": rec}


@app.delete("/api/v1/agent/job-profiles/{job_id}")
def revoke_agent_job_profile(
    request: Request,
    job_id: str,
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    _check_token(request, authorization)
    _require_unlocked(request)
    if not revoke_job_profile(job_id):
        raise HTTPException(status_code=404, detail="job_profile_not_found")
    return {"status": "ok", "id": job_id}


@app.post("/api/v1/agent/job-profiles/{job_id}/run")
def run_agent_job_profile(
    request: Request,
    job_id: str,
    data: dict[str, Any],
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    _check_token(request, authorization)
    _require_unlocked(request)
    pm = _get_pm(request)
    profile = get_job_profile(job_id)
    if not profile or profile.get("revoked_at_utc"):
        raise HTTPException(status_code=404, detail="job_profile_not_found")

    requested_fp = str(data.get("fingerprint", "")).strip() or _active_fingerprint(pm)
    profile_fp = str(profile.get("fingerprint", "")).strip()
    if requested_fp != profile_fp:
        raise HTTPException(status_code=403, detail="job_profile_fingerprint_mismatch")

    allow_policy_drift = bool(data.get("allow_policy_drift", False))
    allow_host_mismatch = bool(data.get("allow_host_mismatch", False))
    bound_host = str(profile.get("host_binding", "")).strip()
    current_host = socket.gethostname()
    if bound_host and bound_host != current_host and not allow_host_mismatch:
        raise HTTPException(status_code=403, detail="job_profile_host_mismatch")

    profile_stamp = str(profile.get("policy_stamp", "")).strip()
    active_stamp = compute_policy_stamp(load_export_policy())
    if profile_stamp and profile_stamp != active_stamp and not allow_policy_drift:
        raise HTTPException(status_code=403, detail="job_profile_policy_mismatch")

    query = str(profile.get("query", "")).strip()
    if not query:
        raise HTTPException(status_code=400, detail="job_profile_query_missing")
    matches = pm.entry_manager.search_entries(query)
    if len(matches) != 1:
        return {
            "status": "error",
            "reason": "ambiguous_or_missing",
            "match_count": len(matches),
            "matches": [
                {
                    "index": idx,
                    "label": label,
                    "kind": etype.value if hasattr(etype, "value") else str(etype),
                    "username": username,
                    "url": url,
                    "archived": archived,
                }
                for idx, label, username, url, archived, etype in matches
            ],
        }
    index, label, _username, _url, _archived, etype = matches[0]
    kind = etype.value if hasattr(etype, "value") else str(etype)
    lease_ttl = int(data.get("lease_ttl", profile.get("lease_ttl", 30)))
    lease_uses = int(data.get("lease_uses", profile.get("lease_uses", 1)))
    lease = issue_lease(
        fingerprint=profile_fp,
        index=int(index),
        kind=str(kind),
        label=str(label),
        ttl_seconds=lease_ttl,
        uses=lease_uses,
        token_id=None,
    )
    return {
        "status": "ok",
        "mode": "lease_issued",
        "job_profile_id": job_id,
        "lease_id": lease.get("id"),
        "fingerprint": profile_fp,
        "index": int(index),
        "kind": str(kind),
        "label": str(label),
        "policy_binding": profile.get("policy_binding"),
        "policy_stamp": profile_stamp or None,
        "active_policy_stamp": active_stamp,
        "lease_expires_at_utc": lease.get("expires_at_utc"),
        "lease_uses_remaining": int(lease.get("uses_remaining", 0)),
    }


@app.get("/api/v1/agent/job-profiles/{job_id}/template")
def template_agent_job_profile(
    request: Request,
    job_id: str,
    authorization: str | None = Header(None),
    mode: str = "cron",
    schedule: str | None = None,
    unit_name: str = "seedpass-agent-job",
    include_manifest: bool = True,
) -> dict[str, Any]:
    _check_token(request, authorization)
    _require_unlocked(request)
    profile = get_job_profile(job_id)
    if not profile or profile.get("revoked_at_utc"):
        raise HTTPException(status_code=404, detail="job_profile_not_found")
    return _build_job_profile_template_payload(
        profile=profile,
        job_id=job_id,
        mode=mode,
        schedule=schedule,
        unit_name=unit_name,
        include_manifest=bool(include_manifest),
    )


@app.post("/api/v1/agent/job-profiles/{job_id}/template")
def template_agent_job_profile_post(
    request: Request,
    job_id: str,
    data: dict[str, Any],
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    _check_token(request, authorization)
    _require_unlocked(request)
    profile = get_job_profile(job_id)
    if not profile or profile.get("revoked_at_utc"):
        raise HTTPException(status_code=404, detail="job_profile_not_found")
    return _build_job_profile_template_payload(
        profile=profile,
        job_id=job_id,
        mode=str(data.get("mode", "cron")),
        schedule=str(data.get("schedule", "")).strip() or None,
        unit_name=str(data.get("unit_name", "seedpass-agent-job")),
        include_manifest=bool(data.get("include_manifest", True)),
    )


@app.post("/api/v1/agent/job-profiles/{job_id}/template/verify")
def verify_agent_job_profile_template(
    request: Request,
    job_id: str,
    data: dict[str, Any],
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    _check_token(request, authorization)
    _require_unlocked(request)
    profile = get_job_profile(job_id)
    if not profile or profile.get("revoked_at_utc"):
        raise HTTPException(status_code=404, detail="job_profile_not_found")
    payload = data.get("template")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="template_required")
    manifest = data.get("manifest")
    if not isinstance(manifest, dict):
        manifest = payload.get("template_manifest")
    if not isinstance(manifest, dict):
        raise HTTPException(status_code=400, detail="template_manifest_required")
    expected = _template_manifest(payload)
    mismatches: list[str] = []
    for key in (
        "template_hash_sha256",
        "policy_stamp",
        "host_binding",
        "job_profile_id",
        "signature_hmac_sha256",
    ):
        if str(manifest.get(key, "")) != str(expected.get(key, "")):
            mismatches.append(key)
    return {
        "status": "ok",
        "valid": len(mismatches) == 0,
        "job_profile_id": job_id,
        "mismatches": mismatches,
    }


@app.get("/api/v1/agent/job-profiles/check")
def check_agent_job_profiles(
    request: Request,
    authorization: str | None = Header(None),
    max_age_days: int = 30,
) -> dict[str, Any]:
    _check_token(request, authorization)
    _require_unlocked(request)
    jobs = list_job_profiles(include_revoked=False)
    active_stamp = compute_policy_stamp(load_export_policy())
    now = datetime.now(timezone.utc)
    findings: list[dict[str, Any]] = []
    for rec in jobs:
        job_id = str(rec.get("id", ""))
        broker = str(rec.get("auth_broker", "")).strip().lower()
        if broker not in {"keyring", "command"}:
            findings.append(
                {
                    "id": "job_profile_unsafe_broker",
                    "severity": "high",
                    "job_id": job_id,
                    "broker": broker,
                }
            )
        profile_stamp = str(rec.get("policy_stamp", "")).strip()
        if profile_stamp and profile_stamp != active_stamp:
            findings.append(
                {
                    "id": "job_profile_policy_mismatch",
                    "severity": "medium",
                    "job_id": job_id,
                    "job_policy_stamp": profile_stamp,
                    "active_policy_stamp": active_stamp,
                }
            )
        bound_host = str(rec.get("host_binding", "")).strip()
        current_host = socket.gethostname()
        if bound_host and bound_host != current_host:
            findings.append(
                {
                    "id": "job_profile_host_mismatch",
                    "severity": "medium",
                    "job_id": job_id,
                    "job_host": bound_host,
                    "current_host": current_host,
                }
            )
        created_at = str(rec.get("created_at_utc", ""))
        if created_at:
            try:
                created_dt = datetime.fromisoformat(created_at)
                if created_dt.tzinfo is None:
                    created_dt = created_dt.replace(tzinfo=timezone.utc)
                age_days = (now - created_dt).days
                if age_days > int(max_age_days):
                    findings.append(
                        {
                            "id": "job_profile_stale",
                            "severity": "low",
                            "job_id": job_id,
                            "age_days": age_days,
                        }
                    )
            except Exception:
                pass
    return {
        "status": "ok",
        "check": "agent_job_profiles",
        "job_profile_count": len(jobs),
        "active_policy_stamp": active_stamp,
        "finding_count": len(findings),
        "findings": findings,
    }


@app.post("/api/v1/agent/recovery/split")
def agent_recovery_split(
    request: Request,
    data: dict[str, Any],
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    _check_token(request, authorization)
    _require_unlocked(request)
    secret = str(data.get("secret", "")).strip()
    if not secret:
        raise HTTPException(status_code=400, detail="secret_required")
    shares = int(data.get("shares", 5))
    threshold = int(data.get("threshold", 3))
    label = str(data.get("label", "default")).strip() or "default"
    try:
        tokens = split_secret(
            secret, total_shares=int(shares), threshold=int(threshold), label=label
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {
        "status": "ok",
        "label": label,
        "threshold": threshold,
        "total_shares": shares,
        "shares": tokens,
    }


@app.post("/api/v1/agent/recovery/recover")
def agent_recovery_recover(
    request: Request,
    data: dict[str, Any],
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    _check_token(request, authorization)
    _require_unlocked(request)
    raw = data.get("shares")
    if not isinstance(raw, list) or not raw:
        raise HTTPException(status_code=400, detail="shares_required")
    shares = [str(v).strip() for v in raw if str(v).strip()]
    if not shares:
        raise HTTPException(status_code=400, detail="shares_required")
    reveal = bool(data.get("reveal", False))
    try:
        secret = recover_secret(shares)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {
        "status": "ok",
        "share_count": len(shares),
        "revealed": reveal,
        "secret": secret if reveal else _mask_value(secret),
    }


@app.post("/api/v1/agent/recovery/drill")
def agent_recovery_drill(
    request: Request,
    data: dict[str, Any],
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    _check_token(request, authorization)
    _require_unlocked(request)
    pm = _get_pm(request)
    backup_path = str(data.get("backup_path", "")).strip()
    if not backup_path:
        raise HTTPException(status_code=400, detail="backup_path_required")
    fingerprint = str(data.get("fingerprint", "")).strip() or _active_fingerprint(pm)
    simulated = bool(data.get("simulated", True))
    raw_max_age = data.get("max_age_days", 30)
    max_age_days = int(raw_max_age) if raw_max_age is not None else None
    report = record_recovery_drill(
        fingerprint=fingerprint,
        backup_path=backup_path,
        simulated=simulated,
        expected_max_age_days=max_age_days,
    )
    return {"status": "ok", "report": report}


@app.get("/api/v1/agent/recovery/drills")
def agent_recovery_drills(
    request: Request,
    authorization: str | None = Header(None),
    limit: int = 20,
) -> dict[str, Any]:
    _check_token(request, authorization)
    _require_unlocked(request)
    records = list_recovery_drills(limit=int(limit))
    return {"status": "ok", "count": len(records), "drills": records}


@app.post("/api/v1/agent/recovery/drills/verify")
def agent_recovery_drills_verify(
    request: Request,
    data: dict[str, Any],
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    _check_token(request, authorization)
    _require_unlocked(request)
    limit = int(data.get("limit", 200))
    result = verify_recovery_drills(limit=limit)
    return {"status": "ok", **result}


@app.get("/api/v1/entry/{entry_id}")
async def get_entry(
    request: Request,
    entry_id: int,
    authorization: str | None = Header(None),
    password: str | None = Header(None, alias="X-SeedPass-Password"),
) -> Any:
    _check_token(request, authorization)
    _require_password(request, password)
    _require_unlocked(request)
    pm = _get_pm(request)
    entry = pm.entry_manager.retrieve_entry(entry_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="Not found")
    kind = str(entry.get("kind", entry.get("type", ""))).strip().lower()
    if kind in {"seed", "ssh", "pgp", "nostr", "managed_account"}:
        policy = load_export_policy()
        _require_high_risk_session(pm, policy, {kind})
    entry = _hydrate_partitioned_entry_if_needed(pm, entry_id, entry)
    return entry


@app.post("/api/v1/entry")
async def create_entry(
    request: Request,
    entry: dict,
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    """Create a new entry.

    If ``entry['type']`` or ``entry['kind']`` specifies ``totp``, ``ssh`` and so
    on, the corresponding entry type is created. When omitted or set to
    ``password`` the behaviour matches the legacy password-entry API.
    """
    _check_token(request, authorization)
    _require_unlocked(request)
    pm = _get_pm(request)

    etype = (entry.get("type") or entry.get("kind") or "password").lower()

    if etype == "password":
        policy_keys = [
            "include_special_chars",
            "allowed_special_chars",
            "special_mode",
            "exclude_ambiguous",
            "min_uppercase",
            "min_lowercase",
            "min_digits",
            "min_special",
        ]
        kwargs = {k: entry.get(k) for k in policy_keys if entry.get(k) is not None}

        index = pm.entry_manager.add_entry(
            entry.get("label"),
            int(entry.get("length", 12)),
            entry.get("username"),
            entry.get("url"),
            **kwargs,
        )
        return {"id": index}

    if etype == "totp":
        index = pm.entry_manager.get_next_index()

        uri = pm.entry_manager.add_totp(
            entry.get("label"),
            pm.KEY_TOTP_DET if entry.get("deterministic", False) else None,
            secret=entry.get("secret"),
            index=entry.get("index"),
            period=int(entry.get("period", 30)),
            digits=int(entry.get("digits", 6)),
            notes=entry.get("notes", ""),
            archived=entry.get("archived", False),
            deterministic=entry.get("deterministic", False),
        )
        return {"id": index, "uri": uri}

    if etype == "ssh":
        index = pm.entry_manager.add_ssh_key(
            entry.get("label"),
            pm.parent_seed,
            index=entry.get("index"),
            notes=entry.get("notes", ""),
            archived=entry.get("archived", False),
        )
        return {"id": index}

    if etype == "pgp":
        index = pm.entry_manager.add_pgp_key(
            entry.get("label"),
            pm.parent_seed,
            index=entry.get("index"),
            key_type=entry.get("key_type", "ed25519"),
            user_id=entry.get("user_id", ""),
            notes=entry.get("notes", ""),
            archived=entry.get("archived", False),
        )
        return {"id": index}

    if etype == "nostr":
        index = pm.entry_manager.add_nostr_key(
            entry.get("label"),
            pm.parent_seed,
            index=entry.get("index"),
            notes=entry.get("notes", ""),
            archived=entry.get("archived", False),
        )
        return {"id": index}

    if etype == "key_value":
        index = pm.entry_manager.add_key_value(
            entry.get("label"),
            entry.get("key"),
            entry.get("value"),
            notes=entry.get("notes", ""),
        )
        return {"id": index}

    if etype in {"seed", "managed_account"}:
        func = (
            pm.entry_manager.add_seed
            if etype == "seed"
            else pm.entry_manager.add_managed_account
        )
        index = func(
            entry.get("label"),
            pm.parent_seed,
            index=entry.get("index"),
            notes=entry.get("notes", ""),
        )
        return {"id": index}

    raise HTTPException(status_code=400, detail="Unsupported entry type")


@app.put("/api/v1/entry/{entry_id}")
def update_entry(
    request: Request,
    entry_id: int,
    entry: dict,
    authorization: str | None = Header(None),
) -> dict[str, str]:
    """Update an existing entry.

    Additional fields like ``period``, ``digits`` and ``value`` are forwarded for
    specialized entry types (e.g. TOTP or key/value entries).
    """
    _check_token(request, authorization)
    _require_unlocked(request)
    pm = _get_pm(request)
    try:
        pm.entry_manager.modify_entry(
            entry_id,
            username=entry.get("username"),
            url=entry.get("url"),
            notes=entry.get("notes"),
            label=entry.get("label"),
            period=entry.get("period"),
            digits=entry.get("digits"),
            key=entry.get("key"),
            value=entry.get("value"),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"status": "ok"}


@app.post("/api/v1/entry/{entry_id}/archive")
def archive_entry(
    request: Request, entry_id: int, authorization: str | None = Header(None)
) -> dict[str, str]:
    """Archive an entry."""
    _check_token(request, authorization)
    _require_unlocked(request)
    pm = _get_pm(request)
    pm.entry_manager.archive_entry(entry_id)
    return {"status": "archived"}


@app.post("/api/v1/entry/{entry_id}/unarchive")
def unarchive_entry(
    request: Request, entry_id: int, authorization: str | None = Header(None)
) -> dict[str, str]:
    """Restore an archived entry."""
    _check_token(request, authorization)
    _require_unlocked(request)
    pm = _get_pm(request)
    pm.entry_manager.restore_entry(entry_id)
    return {"status": "active"}


@app.get("/api/v1/config/{key}")
def get_config(
    request: Request, key: str, authorization: str | None = Header(None)
) -> Any:
    _check_token(request, authorization)
    _require_unlocked(request)
    if key in _SENSITIVE_CONFIG_KEYS:
        raise HTTPException(
            status_code=403, detail="Access to sensitive config is denied"
        )
    pm = _get_pm(request)
    value = pm.config_manager.load_config(require_pin=False).get(key)

    if value is None:
        raise HTTPException(status_code=404, detail="Not found")
    return {"key": key, "value": value}


@app.put("/api/v1/config/{key}")
def update_config(
    request: Request,
    key: str,
    data: dict,
    authorization: str | None = Header(None),
) -> dict[str, str]:
    """Update a configuration setting."""
    _check_token(request, authorization)
    _require_unlocked(request)
    if key in _SENSITIVE_CONFIG_KEYS:
        raise HTTPException(
            status_code=403, detail="Updating sensitive config keys is not allowed"
        )
    pm = _get_pm(request)
    cfg = pm.config_manager
    mapping = {
        "relays": lambda v: cfg.set_relays(v, require_pin=False),
        "pin": cfg.set_pin,
        "password_hash": cfg.set_password_hash,
        "inactivity_timeout": lambda v: cfg.set_inactivity_timeout(float(v)),
        "additional_backup_path": cfg.set_additional_backup_path,
        "secret_mode_enabled": cfg.set_secret_mode_enabled,
        "clipboard_clear_delay": lambda v: cfg.set_clipboard_clear_delay(int(v)),
        "quick_unlock": cfg.set_quick_unlock,
    }

    action = mapping.get(key)

    if action is None:
        raise HTTPException(status_code=400, detail="Unknown key")

    if "value" not in data:
        raise HTTPException(status_code=400, detail="Missing value")

    action(data["value"])
    return {"status": "ok"}


@app.post("/api/v1/secret-mode")
def set_secret_mode(
    request: Request, data: dict, authorization: str | None = Header(None)
) -> dict[str, str]:
    """Enable/disable secret mode and set the clipboard delay."""
    _check_token(request, authorization)
    _require_unlocked(request)
    pm = _get_pm(request)
    enabled = data.get("enabled")

    delay = data.get("delay")

    if enabled is None or delay is None:
        raise HTTPException(status_code=400, detail="Missing fields")
    cfg = pm.config_manager
    cfg.set_secret_mode_enabled(bool(enabled))
    cfg.set_clipboard_clear_delay(int(delay))
    pm.secret_mode_enabled = bool(enabled)
    pm.clipboard_clear_delay = int(delay)
    return {"status": "ok"}


@app.get("/api/v1/fingerprint")
def list_fingerprints(
    request: Request, authorization: str | None = Header(None)
) -> List[str]:
    _check_token(request, authorization)
    pm = _get_pm(request)
    return pm.fingerprint_manager.list_fingerprints()


@app.post("/api/v1/fingerprint")
def add_fingerprint(
    request: Request, authorization: str | None = Header(None)
) -> dict[str, str]:
    """Create a new seed profile."""
    _check_token(request, authorization)
    _require_unlocked(request)
    pm = _get_pm(request)
    pm.add_new_fingerprint()
    return {"status": "ok"}


@app.delete("/api/v1/fingerprint/{fingerprint}")
def remove_fingerprint(
    request: Request, fingerprint: str, authorization: str | None = Header(None)
) -> dict[str, str]:
    """Remove a seed profile."""
    _check_token(request, authorization)
    _require_unlocked(request)
    pm = _get_pm(request)
    pm.fingerprint_manager.remove_fingerprint(fingerprint)
    return {"status": "deleted"}


@app.post("/api/v1/fingerprint/select")
def select_fingerprint(
    request: Request, data: dict, authorization: str | None = Header(None)
) -> dict[str, str]:
    """Switch the active seed profile."""
    _check_token(request, authorization)
    pm = _get_pm(request)
    fp = data.get("fingerprint")

    if not fp:
        raise HTTPException(status_code=400, detail="Missing fingerprint")
    pm.select_fingerprint(fp)
    return {"status": "ok"}


@app.get("/api/v1/totp/export")
def export_totp(
    request: Request,
    authorization: str | None = Header(None),
    password: str | None = Header(None, alias="X-SeedPass-Password"),
    agent_profile: str | None = Header(None, alias="X-SeedPass-Agent-Profile"),
) -> dict:
    """Return all stored TOTP entries in JSON format."""
    _check_token(request, authorization)
    _require_password(request, password)
    _require_unlocked(request)
    if _header_truthy(agent_profile):
        policy = load_export_policy()
        allowed, reason = evaluate_kind_export(policy, EntryType.TOTP.value)
        if not allowed:
            record_export_policy_event(
                "export_denied",
                {
                    "source": "api:totp_export",
                    "kind": EntryType.TOTP.value,
                    "reason": reason,
                },
            )
            raise HTTPException(
                status_code=403,
                detail=reason,
            )
        record_export_policy_event(
            "export_allowed",
            {"source": "api:totp_export", "kind": EntryType.TOTP.value},
        )
    pm = _get_pm(request)
    key = getattr(pm, "KEY_TOTP_DET", None) or getattr(pm, "parent_seed", None)
    return pm.entry_manager.export_totp_entries(key)


@app.get("/api/v1/totp")
def get_totp_codes(
    request: Request,
    authorization: str | None = Header(None),
    password: str | None = Header(None, alias="X-SeedPass-Password"),
) -> dict:
    """Return active TOTP codes with remaining seconds."""
    _check_token(request, authorization)
    _require_password(request, password)
    _require_unlocked(request)
    pm = _get_pm(request)
    entries = pm.entry_manager.list_entries(
        filter_kinds=[EntryType.TOTP.value], include_archived=False
    )
    codes = []
    for idx, label, _u, _url, _arch in entries:
        key = getattr(pm, "KEY_TOTP_DET", None) or getattr(pm, "parent_seed", None)
        code = pm.entry_manager.get_totp_code(idx, key)

        rem = pm.entry_manager.get_totp_time_remaining(idx)

        codes.append(
            {"id": idx, "label": label, "code": code, "seconds_remaining": rem}
        )
    return {"codes": codes}


@app.get("/api/v1/stats")
def get_profile_stats(
    request: Request, authorization: str | None = Header(None)
) -> dict:
    """Return statistics about the active seed profile."""
    _check_token(request, authorization)
    _require_unlocked(request)
    pm = _get_pm(request)
    return pm.get_profile_stats()


@app.get("/api/v1/notifications")
def get_notifications(
    request: Request, authorization: str | None = Header(None)
) -> List[dict]:
    """Return and clear queued notifications."""
    _check_token(request, authorization)
    pm = _get_pm(request)
    notes = []
    while True:
        try:
            note = pm.notifications.get_nowait()
        except queue.Empty:
            break
        notes.append({"level": note.level, "message": note.message})
    return notes


@app.get("/api/v1/nostr/pubkey")
def get_nostr_pubkey(request: Request, authorization: str | None = Header(None)) -> Any:
    _check_token(request, authorization)
    _require_unlocked(request)
    pm = _get_pm(request)
    return {"npub": pm.nostr_client.key_manager.get_npub()}


@app.get("/api/v1/relays")
def list_relays(request: Request, authorization: str | None = Header(None)) -> dict:
    """Return the configured Nostr relays."""
    _check_token(request, authorization)
    _require_unlocked(request)
    pm = _get_pm(request)
    cfg = pm.config_manager.load_config(require_pin=False)
    return {"relays": cfg.get("relays", [])}


@app.post("/api/v1/relays")
def add_relay(
    request: Request, data: dict, authorization: str | None = Header(None)
) -> dict[str, str]:
    """Add a relay URL to the configuration."""
    _check_token(request, authorization)
    _require_unlocked(request)
    pm = _get_pm(request)
    url = data.get("url")

    if not url:
        raise HTTPException(status_code=400, detail="Missing url")
    cfg = pm.config_manager.load_config(require_pin=False)
    relays = cfg.get("relays", [])

    if url in relays:
        raise HTTPException(status_code=400, detail="Relay already present")
    relays.append(url)
    pm.config_manager.set_relays(relays, require_pin=False)
    _reload_relays(request, relays)
    return {"status": "ok"}


@app.delete("/api/v1/relays/{idx}")
def remove_relay(
    request: Request, idx: int, authorization: str | None = Header(None)
) -> dict[str, str]:
    """Remove a relay by its index (1-based)."""
    _check_token(request, authorization)
    _require_unlocked(request)
    pm = _get_pm(request)
    cfg = pm.config_manager.load_config(require_pin=False)
    relays = cfg.get("relays", [])

    if not (1 <= idx <= len(relays)):
        raise HTTPException(status_code=400, detail="Invalid index")
    if len(relays) == 1:
        raise HTTPException(status_code=400, detail="At least one relay required")
    relays.pop(idx - 1)
    pm.config_manager.set_relays(relays, require_pin=False)
    _reload_relays(request, relays)
    return {"status": "ok"}


@app.post("/api/v1/relays/reset")
def reset_relays(
    request: Request, authorization: str | None = Header(None)
) -> dict[str, str]:
    """Reset relay list to defaults."""
    _check_token(request, authorization)
    _require_unlocked(request)
    pm = _get_pm(request)
    from nostr.client import DEFAULT_RELAYS

    relays = list(DEFAULT_RELAYS)
    pm.config_manager.set_relays(relays, require_pin=False)
    _reload_relays(request, relays)
    return {"status": "ok"}


@app.post("/api/v1/checksum/verify")
def verify_checksum(
    request: Request, authorization: str | None = Header(None)
) -> dict[str, str]:
    """Verify the SeedPass script checksum."""
    _check_token(request, authorization)
    _require_unlocked(request)
    pm = _get_pm(request)
    pm.handle_verify_checksum()
    return {"status": "ok"}


@app.post("/api/v1/checksum/update")
def update_checksum(
    request: Request, authorization: str | None = Header(None)
) -> dict[str, str]:
    """Regenerate the script checksum file."""
    _check_token(request, authorization)
    _require_unlocked(request)
    pm = _get_pm(request)
    pm.handle_update_script_checksum()
    return {"status": "ok"}


@app.get("/api/v1/export/check")
def export_check(
    request: Request,
    authorization: str | None = Header(None),
    mode: str = "full",
    kind: str | None = None,
) -> dict[str, Any]:
    """Dry-run export policy decision for agent workflows."""
    _check_token(request, authorization)
    _require_unlocked(request)

    mode_l = mode.strip().lower()
    if mode_l not in {"full", "filtered", "kind"}:
        raise HTTPException(
            status_code=400,
            detail="invalid_mode",
        )

    policy = load_export_policy()
    allowed = False
    reason = "policy_deny:unknown"
    checked_kind: str | None = None
    if mode_l == "full":
        allowed, reason = evaluate_full_export(policy)
    elif mode_l == "filtered":
        allowed = True
        reason = "policy_allow:filtered_export"
    else:
        if not kind:
            raise HTTPException(status_code=400, detail="missing_kind")
        checked_kind = kind
        allowed, reason = evaluate_kind_export(policy, kind)

    return {
        "status": "ok",
        "mode": mode_l,
        "allowed": bool(allowed),
        "reason": reason,
        "kind": checked_kind,
        "allow_kinds": sorted(set(policy.get("allow_kinds", []))),
        "allow_export_import": bool(policy.get("allow_export_import", False)),
    }


@app.post("/api/v1/export/manifest/verify")
def verify_export_manifest(
    request: Request, package: dict[str, Any], authorization: str | None = Header(None)
) -> dict[str, Any]:
    """Verify a policy-filtered export package against current export policy."""
    _check_token(request, authorization)
    policy = load_export_policy()
    valid, errors = verify_filtered_export_package(package, policy)
    return {
        "status": "ok",
        "valid": bool(valid),
        "policy_stamp_current": compute_policy_stamp(policy),
        "policy_stamp_manifest": str(
            (package.get("_export_manifest") or {}).get("policy_stamp", "")
        ),
        "errors": errors,
    }


@app.post("/api/v1/vault/export")
def export_vault(
    request: Request,
    authorization: str | None = Header(None),
    password: str | None = Header(None, alias="X-SeedPass-Password"),
    agent_profile: str | None = Header(None, alias="X-SeedPass-Agent-Profile"),
    policy_filtered: str | None = Header(None, alias="X-SeedPass-Policy-Filtered"),
    approval_id: str | None = Header(None, alias="X-SeedPass-Approval-Id"),
):
    """Export the vault and return the encrypted file."""
    _check_token(request, authorization)
    _require_password(request, password)
    _require_unlocked(request)
    is_agent = _header_truthy(agent_profile)
    is_filtered = _header_truthy(policy_filtered)
    pm = _get_pm(request)
    if is_agent:
        policy = load_export_policy()
        if is_filtered:
            _require_high_risk_session(pm, policy, set(allowed_kinds(policy)))
            index_data = pm.vault.load_index()
            filtered = build_policy_filtered_export_package(index_data, policy)
            payload = json.dumps(
                filtered, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            data = pm.vault.encryption_manager.encrypt_data(payload)
            record_export_policy_event(
                "export_allowed",
                {
                    "source": "api:vault_export",
                    "mode": "filtered",
                    "allowed_kinds": sorted(list(allowed_kinds(policy))),
                    "policy_stamp": filtered.get("_export_manifest", {}).get(
                        "policy_stamp"
                    ),
                },
            )
            return Response(content=data, media_type="application/octet-stream")
        allowed, reason = evaluate_full_export(policy)
        if not allowed:
            record_export_policy_event(
                "export_denied",
                {"source": "api:vault_export", "mode": "full", "reason": reason},
            )
            raise HTTPException(
                status_code=403,
                detail=reason,
            )
        if approval_required(policy, "export"):
            if not approval_id:
                reason = "policy_deny:approval_required"
                record_export_policy_event(
                    "export_denied",
                    {"source": "api:vault_export", "mode": "full", "reason": reason},
                )
                raise HTTPException(status_code=403, detail=reason)
            ok, approval_reason = consume_approval(
                approval_id=approval_id,
                action="export",
                resource="vault:full",
            )
            if not ok:
                reason = f"policy_deny:{approval_reason}"
                record_export_policy_event(
                    "export_denied",
                    {"source": "api:vault_export", "mode": "full", "reason": reason},
                )
                raise HTTPException(status_code=403, detail=reason)
        _require_high_risk_session(pm, policy, _policy_isolation_kinds(policy))
        record_export_policy_event(
            "export_allowed",
            {
                "source": "api:vault_export",
                "mode": "full",
                "approval_id": approval_id,
            },
        )
    path = pm.handle_export_database()
    if path is None:
        raise HTTPException(status_code=500, detail="Export failed")
    data = Path(path).read_bytes()
    return Response(content=data, media_type="application/octet-stream")


@app.post("/api/v1/vault/import")
async def import_vault(
    request: Request, authorization: str | None = Header(None)
) -> dict[str, str]:
    """Import a vault backup from a file upload or a server path."""
    _check_token(request, authorization)
    _require_unlocked(request)
    pm = _get_pm(request)

    ctype = request.headers.get("content-type", "")

    if ctype.startswith("multipart/form-data"):
        form = await request.form()
        file = form.get("file")

        if file is None:
            raise HTTPException(status_code=400, detail="Missing file")
        data = await file.read(_MAX_IMPORT_BYTES + 1)
        if len(data) > _MAX_IMPORT_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"Uploaded file exceeds max size of {_MAX_IMPORT_BYTES} bytes",
            )

        def _handle_upload(file_data: bytes) -> None:
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp.write(file_data)
                tmp_path = Path(tmp.name)
            os.chmod(tmp_path, 0o600)
            try:
                pm.handle_import_database(tmp_path)
            finally:
                os.unlink(tmp_path)

        await asyncio.to_thread(_handle_upload, data)
    else:
        body = await request.json()
        path_str = body.get("path")

        if not path_str:
            raise HTTPException(status_code=400, detail="Missing file or path")

        path = _validate_encryption_path(request, Path(path_str))
        if not str(path).endswith(".json.enc"):
            raise HTTPException(
                status_code=400,
                detail="Selected file must be a '.json.enc' backup",
            )

        await asyncio.to_thread(pm.handle_import_database, path)

    if hasattr(pm, "sync_vault_async"):
        await pm.sync_vault_async()
    else:
        # Fallback for older PM implementations or mocks
        await asyncio.to_thread(pm.sync_vault)
    return {"status": "ok"}


@app.post("/api/v1/vault/backup-parent-seed")
def backup_parent_seed(
    request: Request,
    data: dict,
    authorization: str | None = Header(None),
    password: str | None = Header(None, alias="X-SeedPass-Password"),
    agent_profile: str | None = Header(None, alias="X-SeedPass-Agent-Profile"),
    approval_id: str | None = Header(None, alias="X-SeedPass-Approval-Id"),
) -> dict[str, str]:
    """Create an encrypted backup of the parent seed after confirmation."""
    _check_token(request, authorization)
    _require_password(request, password)
    _require_unlocked(request)
    pm = _get_pm(request)
    policy = load_export_policy()
    _require_high_risk_session(pm, policy, {"seed"})
    if _header_truthy(agent_profile):
        if approval_required(policy, "reveal_parent_seed"):
            if not approval_id:
                reason = "policy_deny:approval_required"
                record_export_policy_event(
                    "approval_denied",
                    {
                        "source": "api:vault_backup_parent_seed",
                        "reason": reason,
                        "action": "reveal_parent_seed",
                    },
                )
                raise HTTPException(status_code=403, detail=reason)
            ok, approval_reason = consume_approval(
                approval_id=approval_id,
                action="reveal_parent_seed",
                resource="vault:parent-seed",
            )
            if not ok:
                reason = f"policy_deny:{approval_reason}"
                record_export_policy_event(
                    "approval_denied",
                    {
                        "source": "api:vault_backup_parent_seed",
                        "reason": reason,
                        "action": "reveal_parent_seed",
                        "approval_id": approval_id,
                    },
                )
                raise HTTPException(status_code=403, detail=reason)

    if not data.get("confirm"):

        raise HTTPException(status_code=400, detail="Confirmation required")

    path_str = data.get("path")

    if not path_str:
        raise HTTPException(status_code=400, detail="Missing path")
    path = Path(path_str)
    resolved_path = _validate_encryption_path(request, path)
    if resolved_path.exists():
        raise HTTPException(status_code=409, detail="File already exists")
    pm.encryption_manager.encrypt_and_save_file(pm.parent_seed.encode("utf-8"), path)
    if _header_truthy(agent_profile):
        record_export_policy_event(
            "approval_consumed",
            {
                "source": "api:vault_backup_parent_seed",
                "action": "reveal_parent_seed",
                "approval_id": approval_id,
                "path": str(path),
            },
        )
    return {"status": "saved", "path": str(path)}


@app.post("/api/v1/change-password")
def change_password(
    request: Request, data: dict, authorization: str | None = Header(None)
) -> dict[str, str]:
    """Change the master password for the active profile."""
    _check_token(request, authorization)
    _require_unlocked(request)
    pm = _get_pm(request)
    pm.change_password(data.get("old", ""), data.get("new", ""))

    return {"status": "ok"}


@app.post("/api/v1/password")
def generate_password(
    request: Request, data: dict, authorization: str | None = Header(None)
) -> dict[str, str]:
    """Generate a password using optional policy overrides."""
    _check_token(request, authorization)
    _require_unlocked(request)
    pm = _get_pm(request)
    length = int(data.get("length", 12))

    policy_keys = [
        "include_special_chars",
        "allowed_special_chars",
        "special_mode",
        "exclude_ambiguous",
        "min_uppercase",
        "min_lowercase",
        "min_digits",
        "min_special",
    ]
    kwargs = {k: data.get(k) for k in policy_keys if data.get(k) is not None}

    util = UtilityService(pm)
    password = util.generate_password(length, **kwargs)
    return {"password": password}


@app.post("/api/v1/vault/lock")
def lock_vault(
    request: Request, authorization: str | None = Header(None)
) -> dict[str, str]:
    """Lock the vault and clear sensitive data from memory."""
    _check_token(request, authorization)
    pm = _get_pm(request)
    pm.lock_vault()
    return {"status": "locked"}


@app.post("/api/v1/vault/unlock")
def unlock_vault(
    request: Request,
    authorization: str | None = Header(None),
    password: str | None = Header(None, alias="X-SeedPass-Password"),
) -> dict[str, float | str]:
    """Unlock the vault using the supplied master password."""
    _check_token(request, authorization)
    if authorization is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    raw_token = authorization.split(" ", 1)[1]
    _enforce_unlock_attempt_limit(request, raw_token)
    pm = _get_pm(request)
    if password is None or not pm.verify_password(password):
        _record_unlock_failure(request, raw_token)
        raise HTTPException(status_code=401, detail="Invalid password")
    duration = pm.unlock_vault(password)
    return {
        "status": "unlocked",
        "duration": float(duration),
        "help_hint": "Use /docs or run `seedpass --help` for command and endpoint discovery.",
    }


@app.post("/api/v1/shutdown")
async def shutdown_server(
    request: Request, authorization: str | None = Header(None)
) -> dict[str, str]:
    _check_token(request, authorization)
    asyncio.get_event_loop().call_soon(sys.exit, 0)

    return {"status": "shutting down"}
