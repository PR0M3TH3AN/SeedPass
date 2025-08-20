"""SeedPass FastAPI server."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
import secrets
import queue
from typing import Any, List, Optional

from datetime import datetime, timedelta, timezone
import jwt
import logging

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.concurrency import run_in_threadpool
import asyncio
import sys
from fastapi.middleware.cors import CORSMiddleware
import hashlib
import hmac

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from slowapi.middleware import SlowAPIMiddleware

from seedpass.core.manager import PasswordManager
from seedpass.core.entry_types import EntryType
from seedpass.core.api import UtilityService


_RATE_LIMIT = int(os.getenv("SEEDPASS_RATE_LIMIT", "100"))
_RATE_WINDOW = int(os.getenv("SEEDPASS_RATE_WINDOW", "60"))
_RATE_LIMIT_STR = f"{_RATE_LIMIT}/{_RATE_WINDOW} seconds"

limiter = Limiter(key_func=get_remote_address, default_limits=[_RATE_LIMIT_STR])
app = FastAPI()

logger = logging.getLogger(__name__)


def _get_pm(request: Request) -> PasswordManager:
    pm = getattr(request.app.state, "pm", None)
    assert pm is not None
    return pm


def _check_token(request: Request, auth: str | None) -> None:
    if auth is None or not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")
    token = auth.split(" ", 1)[1]
    jwt_secret = getattr(request.app.state, "jwt_secret", "")
    token_hash = getattr(request.app.state, "token_hash", "")
    try:
        jwt.decode(token, jwt_secret, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Unauthorized")
    if not hmac.compare_digest(hashlib.sha256(token.encode()).hexdigest(), token_hash):
        raise HTTPException(status_code=401, detail="Unauthorized")


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


def start_server(fingerprint: str | None = None) -> str:
    """Initialize global state and return a short-lived JWT token.

    Parameters
    ----------
    fingerprint:
        Optional seed profile fingerprint to select before starting the server.
    """
    if fingerprint is None:
        pm = PasswordManager()
    else:
        pm = PasswordManager(fingerprint=fingerprint)
    app.state.pm = pm
    app.state.jwt_secret = secrets.token_urlsafe(32)
    payload = {"exp": datetime.now(timezone.utc) + timedelta(minutes=5)}
    raw_token = jwt.encode(payload, app.state.jwt_secret, algorithm="HS256")
    app.state.token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    if not getattr(app.state, "limiter", None):
        app.state.limiter = limiter
        app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
        app.add_middleware(SlowAPIMiddleware)
    origins = [
        o.strip()
        for o in os.getenv("SEEDPASS_CORS_ORIGINS", "").split(",")
        if o.strip()
    ]
    if origins and app.middleware_stack is None:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    return raw_token


def _require_password(request: Request, password: str | None) -> None:
    pm = _get_pm(request)
    if password is None or not pm.verify_password(password):
        raise HTTPException(status_code=401, detail="Invalid password")


def _validate_encryption_path(request: Request, path: Path) -> Path:
    """Validate and normalize ``path`` within the active fingerprint directory.

    Returns the resolved absolute path if validation succeeds.
    """

    pm = _get_pm(request)
    try:
        return pm.encryption_manager.resolve_relative_path(path)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/entry")
async def search_entry(
    request: Request, query: str, authorization: str | None = Header(None)
) -> List[Any]:
    _check_token(request, authorization)
    pm = _get_pm(request)
    results = await run_in_threadpool(pm.entry_manager.search_entries, query)
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


@app.get("/api/v1/entry/{entry_id}")
async def get_entry(
    request: Request,
    entry_id: int,
    authorization: str | None = Header(None),
    password: str | None = Header(None, alias="X-SeedPass-Password"),
) -> Any:
    _check_token(request, authorization)
    _require_password(request, password)
    pm = _get_pm(request)
    entry = await run_in_threadpool(pm.entry_manager.retrieve_entry, entry_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="Not found")
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

        index = await run_in_threadpool(
            pm.entry_manager.add_entry,
            entry.get("label"),
            int(entry.get("length", 12)),
            entry.get("username"),
            entry.get("url"),
            **kwargs,
        )
        return {"id": index}

    if etype == "totp":
        index = await run_in_threadpool(pm.entry_manager.get_next_index)

        uri = await run_in_threadpool(
            pm.entry_manager.add_totp,
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
        index = await run_in_threadpool(
            pm.entry_manager.add_ssh_key,
            entry.get("label"),
            pm.parent_seed,
            index=entry.get("index"),
            notes=entry.get("notes", ""),
            archived=entry.get("archived", False),
        )
        return {"id": index}

    if etype == "pgp":
        index = await run_in_threadpool(
            pm.entry_manager.add_pgp_key,
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
        index = await run_in_threadpool(
            pm.entry_manager.add_nostr_key,
            entry.get("label"),
            pm.parent_seed,
            index=entry.get("index"),
            notes=entry.get("notes", ""),
            archived=entry.get("archived", False),
        )
        return {"id": index}

    if etype == "key_value":
        index = await run_in_threadpool(
            pm.entry_manager.add_key_value,
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
        index = await run_in_threadpool(
            func,
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
    pm = _get_pm(request)
    pm.entry_manager.archive_entry(entry_id)
    return {"status": "archived"}


@app.post("/api/v1/entry/{entry_id}/unarchive")
def unarchive_entry(
    request: Request, entry_id: int, authorization: str | None = Header(None)
) -> dict[str, str]:
    """Restore an archived entry."""
    _check_token(request, authorization)
    pm = _get_pm(request)
    pm.entry_manager.restore_entry(entry_id)
    return {"status": "active"}


@app.get("/api/v1/config/{key}")
def get_config(
    request: Request, key: str, authorization: str | None = Header(None)
) -> Any:
    _check_token(request, authorization)
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
    pm = _get_pm(request)
    pm.add_new_fingerprint()
    return {"status": "ok"}


@app.delete("/api/v1/fingerprint/{fingerprint}")
def remove_fingerprint(
    request: Request, fingerprint: str, authorization: str | None = Header(None)
) -> dict[str, str]:
    """Remove a seed profile."""
    _check_token(request, authorization)
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
) -> dict:
    """Return all stored TOTP entries in JSON format."""
    _check_token(request, authorization)
    _require_password(request, password)
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
    pm = _get_pm(request)
    return {"npub": pm.nostr_client.key_manager.get_npub()}


@app.get("/api/v1/relays")
def list_relays(request: Request, authorization: str | None = Header(None)) -> dict:
    """Return the configured Nostr relays."""
    _check_token(request, authorization)
    pm = _get_pm(request)
    cfg = pm.config_manager.load_config(require_pin=False)
    return {"relays": cfg.get("relays", [])}


@app.post("/api/v1/relays")
def add_relay(
    request: Request, data: dict, authorization: str | None = Header(None)
) -> dict[str, str]:
    """Add a relay URL to the configuration."""
    _check_token(request, authorization)
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
    pm = _get_pm(request)
    pm.handle_verify_checksum()
    return {"status": "ok"}


@app.post("/api/v1/checksum/update")
def update_checksum(
    request: Request, authorization: str | None = Header(None)
) -> dict[str, str]:
    """Regenerate the script checksum file."""
    _check_token(request, authorization)
    pm = _get_pm(request)
    pm.handle_update_script_checksum()
    return {"status": "ok"}


@app.post("/api/v1/vault/export")
def export_vault(
    request: Request,
    authorization: str | None = Header(None),
    password: str | None = Header(None, alias="X-SeedPass-Password"),
):
    """Export the vault and return the encrypted file."""
    _check_token(request, authorization)
    _require_password(request, password)
    pm = _get_pm(request)
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
    pm = _get_pm(request)

    ctype = request.headers.get("content-type", "")

    if ctype.startswith("multipart/form-data"):
        form = await request.form()
        file = form.get("file")

        if file is None:
            raise HTTPException(status_code=400, detail="Missing file")
        data = await file.read()
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(data)
            tmp_path = Path(tmp.name)
        try:
            pm.handle_import_database(tmp_path)
        finally:
            os.unlink(tmp_path)
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

        pm.handle_import_database(path)
    pm.sync_vault()
    return {"status": "ok"}


@app.post("/api/v1/vault/backup-parent-seed")
def backup_parent_seed(
    request: Request,
    data: dict,
    authorization: str | None = Header(None),
    password: str | None = Header(None, alias="X-SeedPass-Password"),
) -> dict[str, str]:
    """Create an encrypted backup of the parent seed after confirmation."""
    _check_token(request, authorization)
    _require_password(request, password)
    pm = _get_pm(request)

    if not data.get("confirm"):

        raise HTTPException(status_code=400, detail="Confirmation required")

    path_str = data.get("path")

    if not path_str:
        raise HTTPException(status_code=400, detail="Missing path")
    path = Path(path_str)
    _validate_encryption_path(request, path)
    pm.encryption_manager.encrypt_and_save_file(pm.parent_seed.encode("utf-8"), path)
    return {"status": "saved", "path": str(path)}


@app.post("/api/v1/change-password")
def change_password(
    request: Request, data: dict, authorization: str | None = Header(None)
) -> dict[str, str]:
    """Change the master password for the active profile."""
    _check_token(request, authorization)
    pm = _get_pm(request)
    pm.change_password(data.get("old", ""), data.get("new", ""))

    return {"status": "ok"}


@app.post("/api/v1/password")
def generate_password(
    request: Request, data: dict, authorization: str | None = Header(None)
) -> dict[str, str]:
    """Generate a password using optional policy overrides."""
    _check_token(request, authorization)
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


@app.post("/api/v1/shutdown")
async def shutdown_server(
    request: Request, authorization: str | None = Header(None)
) -> dict[str, str]:
    _check_token(request, authorization)
    asyncio.get_event_loop().call_soon(sys.exit, 0)

    return {"status": "shutting down"}
