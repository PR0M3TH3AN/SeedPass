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

from fastapi import FastAPI, Header, HTTPException, Request, Response
import asyncio
import sys
from fastapi.middleware.cors import CORSMiddleware

from seedpass.core.manager import PasswordManager
from seedpass.core.entry_types import EntryType
from seedpass.core.api import UtilityService


app = FastAPI()

_pm: Optional[PasswordManager] = None
_token: str = ""
_jwt_secret: str = ""


def _check_token(auth: str | None) -> None:
    if auth is None or not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")
    token = auth.split(" ", 1)[1]
    try:
        jwt.decode(token, _jwt_secret, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Unauthorized")


def _reload_relays(relays: list[str]) -> None:
    """Reload the Nostr client with a new relay list."""
    assert _pm is not None
    try:
        _pm.nostr_client.close_client_pool()
    except Exception:
        pass
    try:
        _pm.nostr_client.relays = relays
        _pm.nostr_client.initialize_client_pool()
    except Exception:
        pass


def start_server(fingerprint: str | None = None) -> str:
    """Initialize global state and return a short-lived JWT token.

    Parameters
    ----------
    fingerprint:
        Optional seed profile fingerprint to select before starting the server.
    """
    global _pm, _token, _jwt_secret
    if fingerprint is None:
        _pm = PasswordManager()
    else:
        _pm = PasswordManager(fingerprint=fingerprint)
    _jwt_secret = secrets.token_urlsafe(32)
    payload = {"exp": datetime.now(timezone.utc) + timedelta(minutes=5)}
    _token = jwt.encode(payload, _jwt_secret, algorithm="HS256")
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
    return _token


def _require_password(password: str | None) -> None:
    assert _pm is not None
    if password is None or not _pm.verify_password(password):
        raise HTTPException(status_code=401, detail="Invalid password")


@app.get("/api/v1/entry")
def search_entry(query: str, authorization: str | None = Header(None)) -> List[Any]:
    _check_token(authorization)
    assert _pm is not None
    results = _pm.entry_manager.search_entries(query)
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
def get_entry(entry_id: int, authorization: str | None = Header(None)) -> Any:
    _check_token(authorization)
    assert _pm is not None
    entry = _pm.entry_manager.retrieve_entry(entry_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="Not found")
    return entry


@app.post("/api/v1/entry")
def create_entry(
    entry: dict,
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    """Create a new entry.

    If ``entry['type']`` or ``entry['kind']`` specifies ``totp``, ``ssh`` and so
    on, the corresponding entry type is created. When omitted or set to
    ``password`` the behaviour matches the legacy password-entry API.
    """
    _check_token(authorization)
    assert _pm is not None

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
        index = _pm.entry_manager.add_entry(
            entry.get("label"),
            int(entry.get("length", 12)),
            entry.get("username"),
            entry.get("url"),
            **kwargs,
        )
        return {"id": index}

    if etype == "totp":
        index = _pm.entry_manager.get_next_index()
        uri = _pm.entry_manager.add_totp(
            entry.get("label"),
            _pm.parent_seed,
            secret=entry.get("secret"),
            index=entry.get("index"),
            period=int(entry.get("period", 30)),
            digits=int(entry.get("digits", 6)),
            notes=entry.get("notes", ""),
            archived=entry.get("archived", False),
        )
        return {"id": index, "uri": uri}

    if etype == "ssh":
        index = _pm.entry_manager.add_ssh_key(
            entry.get("label"),
            _pm.parent_seed,
            index=entry.get("index"),
            notes=entry.get("notes", ""),
            archived=entry.get("archived", False),
        )
        return {"id": index}

    if etype == "pgp":
        index = _pm.entry_manager.add_pgp_key(
            entry.get("label"),
            _pm.parent_seed,
            index=entry.get("index"),
            key_type=entry.get("key_type", "ed25519"),
            user_id=entry.get("user_id", ""),
            notes=entry.get("notes", ""),
            archived=entry.get("archived", False),
        )
        return {"id": index}

    if etype == "nostr":
        index = _pm.entry_manager.add_nostr_key(
            entry.get("label"),
            _pm.parent_seed,
            index=entry.get("index"),
            notes=entry.get("notes", ""),
            archived=entry.get("archived", False),
        )
        return {"id": index}

    if etype == "key_value":
        index = _pm.entry_manager.add_key_value(
            entry.get("label"),
            entry.get("key"),
            entry.get("value"),
            notes=entry.get("notes", ""),
        )
        return {"id": index}

    if etype in {"seed", "managed_account"}:
        func = (
            _pm.entry_manager.add_seed
            if etype == "seed"
            else _pm.entry_manager.add_managed_account
        )
        index = func(
            entry.get("label"),
            _pm.parent_seed,
            index=entry.get("index"),
            notes=entry.get("notes", ""),
        )
        return {"id": index}

    raise HTTPException(status_code=400, detail="Unsupported entry type")


@app.put("/api/v1/entry/{entry_id}")
def update_entry(
    entry_id: int,
    entry: dict,
    authorization: str | None = Header(None),
) -> dict[str, str]:
    """Update an existing entry.

    Additional fields like ``period``, ``digits`` and ``value`` are forwarded for
    specialized entry types (e.g. TOTP or key/value entries).
    """
    _check_token(authorization)
    assert _pm is not None
    try:
        _pm.entry_manager.modify_entry(
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
    entry_id: int, authorization: str | None = Header(None)
) -> dict[str, str]:
    """Archive an entry."""
    _check_token(authorization)
    assert _pm is not None
    _pm.entry_manager.archive_entry(entry_id)
    return {"status": "archived"}


@app.post("/api/v1/entry/{entry_id}/unarchive")
def unarchive_entry(
    entry_id: int, authorization: str | None = Header(None)
) -> dict[str, str]:
    """Restore an archived entry."""
    _check_token(authorization)
    assert _pm is not None
    _pm.entry_manager.restore_entry(entry_id)
    return {"status": "active"}


@app.get("/api/v1/config/{key}")
def get_config(key: str, authorization: str | None = Header(None)) -> Any:
    _check_token(authorization)
    assert _pm is not None
    value = _pm.config_manager.load_config(require_pin=False).get(key)
    if value is None:
        raise HTTPException(status_code=404, detail="Not found")
    return {"key": key, "value": value}


@app.put("/api/v1/config/{key}")
def update_config(
    key: str, data: dict, authorization: str | None = Header(None)
) -> dict[str, str]:
    """Update a configuration setting."""
    _check_token(authorization)
    assert _pm is not None
    cfg = _pm.config_manager
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
    data: dict, authorization: str | None = Header(None)
) -> dict[str, str]:
    """Enable/disable secret mode and set the clipboard delay."""
    _check_token(authorization)
    assert _pm is not None
    enabled = data.get("enabled")
    delay = data.get("delay")
    if enabled is None or delay is None:
        raise HTTPException(status_code=400, detail="Missing fields")
    cfg = _pm.config_manager
    cfg.set_secret_mode_enabled(bool(enabled))
    cfg.set_clipboard_clear_delay(int(delay))
    _pm.secret_mode_enabled = bool(enabled)
    _pm.clipboard_clear_delay = int(delay)
    return {"status": "ok"}


@app.get("/api/v1/fingerprint")
def list_fingerprints(authorization: str | None = Header(None)) -> List[str]:
    _check_token(authorization)
    assert _pm is not None
    return _pm.fingerprint_manager.list_fingerprints()


@app.post("/api/v1/fingerprint")
def add_fingerprint(authorization: str | None = Header(None)) -> dict[str, str]:
    """Create a new seed profile."""
    _check_token(authorization)
    assert _pm is not None
    _pm.add_new_fingerprint()
    return {"status": "ok"}


@app.delete("/api/v1/fingerprint/{fingerprint}")
def remove_fingerprint(
    fingerprint: str, authorization: str | None = Header(None)
) -> dict[str, str]:
    """Remove a seed profile."""
    _check_token(authorization)
    assert _pm is not None
    _pm.fingerprint_manager.remove_fingerprint(fingerprint)
    return {"status": "deleted"}


@app.post("/api/v1/fingerprint/select")
def select_fingerprint(
    data: dict, authorization: str | None = Header(None)
) -> dict[str, str]:
    """Switch the active seed profile."""
    _check_token(authorization)
    assert _pm is not None
    fp = data.get("fingerprint")
    if not fp:
        raise HTTPException(status_code=400, detail="Missing fingerprint")
    _pm.select_fingerprint(fp)
    return {"status": "ok"}


@app.get("/api/v1/totp/export")
def export_totp(authorization: str | None = Header(None)) -> dict:
    """Return all stored TOTP entries in JSON format."""
    _check_token(authorization)
    assert _pm is not None
    return _pm.entry_manager.export_totp_entries(_pm.parent_seed)


@app.get("/api/v1/totp")
def get_totp_codes(authorization: str | None = Header(None)) -> dict:
    """Return active TOTP codes with remaining seconds."""
    _check_token(authorization)
    assert _pm is not None
    entries = _pm.entry_manager.list_entries(
        filter_kind=EntryType.TOTP.value, include_archived=False
    )
    codes = []
    for idx, label, _u, _url, _arch in entries:
        code = _pm.entry_manager.get_totp_code(idx, _pm.parent_seed)
        rem = _pm.entry_manager.get_totp_time_remaining(idx)
        codes.append(
            {"id": idx, "label": label, "code": code, "seconds_remaining": rem}
        )
    return {"codes": codes}


@app.get("/api/v1/stats")
def get_profile_stats(authorization: str | None = Header(None)) -> dict:
    """Return statistics about the active seed profile."""
    _check_token(authorization)
    assert _pm is not None
    return _pm.get_profile_stats()


@app.get("/api/v1/notifications")
def get_notifications(authorization: str | None = Header(None)) -> List[dict]:
    """Return and clear queued notifications."""
    _check_token(authorization)
    assert _pm is not None
    notes = []
    while True:
        try:
            note = _pm.notifications.get_nowait()
        except queue.Empty:
            break
        notes.append({"level": note.level, "message": note.message})
    return notes


@app.get("/api/v1/parent-seed")
def get_parent_seed(
    authorization: str | None = Header(None),
    file: str | None = None,
    password: str | None = Header(None, alias="X-SeedPass-Password"),
) -> dict:
    """Return the parent seed or save it as an encrypted backup."""
    _check_token(authorization)
    _require_password(password)
    assert _pm is not None
    if file:
        path = Path(file)
        _pm.encryption_manager.encrypt_and_save_file(
            _pm.parent_seed.encode("utf-8"), path
        )
        return {"status": "saved", "path": str(path)}
    return {"seed": _pm.parent_seed}


@app.get("/api/v1/nostr/pubkey")
def get_nostr_pubkey(authorization: str | None = Header(None)) -> Any:
    _check_token(authorization)
    assert _pm is not None
    return {"npub": _pm.nostr_client.key_manager.get_npub()}


@app.get("/api/v1/relays")
def list_relays(authorization: str | None = Header(None)) -> dict:
    """Return the configured Nostr relays."""
    _check_token(authorization)
    assert _pm is not None
    cfg = _pm.config_manager.load_config(require_pin=False)
    return {"relays": cfg.get("relays", [])}


@app.post("/api/v1/relays")
def add_relay(data: dict, authorization: str | None = Header(None)) -> dict[str, str]:
    """Add a relay URL to the configuration."""
    _check_token(authorization)
    assert _pm is not None
    url = data.get("url")
    if not url:
        raise HTTPException(status_code=400, detail="Missing url")
    cfg = _pm.config_manager.load_config(require_pin=False)
    relays = cfg.get("relays", [])
    if url in relays:
        raise HTTPException(status_code=400, detail="Relay already present")
    relays.append(url)
    _pm.config_manager.set_relays(relays, require_pin=False)
    _reload_relays(relays)
    return {"status": "ok"}


@app.delete("/api/v1/relays/{idx}")
def remove_relay(idx: int, authorization: str | None = Header(None)) -> dict[str, str]:
    """Remove a relay by its index (1-based)."""
    _check_token(authorization)
    assert _pm is not None
    cfg = _pm.config_manager.load_config(require_pin=False)
    relays = cfg.get("relays", [])
    if not (1 <= idx <= len(relays)):
        raise HTTPException(status_code=400, detail="Invalid index")
    if len(relays) == 1:
        raise HTTPException(status_code=400, detail="At least one relay required")
    relays.pop(idx - 1)
    _pm.config_manager.set_relays(relays, require_pin=False)
    _reload_relays(relays)
    return {"status": "ok"}


@app.post("/api/v1/relays/reset")
def reset_relays(authorization: str | None = Header(None)) -> dict[str, str]:
    """Reset relay list to defaults."""
    _check_token(authorization)
    assert _pm is not None
    from nostr.client import DEFAULT_RELAYS

    relays = list(DEFAULT_RELAYS)
    _pm.config_manager.set_relays(relays, require_pin=False)
    _reload_relays(relays)
    return {"status": "ok"}


@app.post("/api/v1/checksum/verify")
def verify_checksum(authorization: str | None = Header(None)) -> dict[str, str]:
    """Verify the SeedPass script checksum."""
    _check_token(authorization)
    assert _pm is not None
    _pm.handle_verify_checksum()
    return {"status": "ok"}


@app.post("/api/v1/checksum/update")
def update_checksum(authorization: str | None = Header(None)) -> dict[str, str]:
    """Regenerate the script checksum file."""
    _check_token(authorization)
    assert _pm is not None
    _pm.handle_update_script_checksum()
    return {"status": "ok"}


@app.post("/api/v1/vault/export")
def export_vault(
    authorization: str | None = Header(None),
    password: str | None = Header(None, alias="X-SeedPass-Password"),
):
    """Export the vault and return the encrypted file."""
    _check_token(authorization)
    _require_password(password)
    assert _pm is not None
    path = _pm.handle_export_database()
    if path is None:
        raise HTTPException(status_code=500, detail="Export failed")
    data = Path(path).read_bytes()
    return Response(content=data, media_type="application/octet-stream")


@app.post("/api/v1/vault/import")
async def import_vault(
    request: Request, authorization: str | None = Header(None)
) -> dict[str, str]:
    """Import a vault backup from a file upload or a server path."""
    _check_token(authorization)
    assert _pm is not None

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
            _pm.handle_import_database(tmp_path)
        finally:
            os.unlink(tmp_path)
    else:
        body = await request.json()
        path = body.get("path")
        if not path:
            raise HTTPException(status_code=400, detail="Missing file or path")
        _pm.handle_import_database(Path(path))
    _pm.sync_vault()
    return {"status": "ok"}


@app.post("/api/v1/vault/backup-parent-seed")
def backup_parent_seed(
    data: dict | None = None, authorization: str | None = Header(None)
) -> dict[str, str]:
    """Backup and reveal the parent seed."""
    _check_token(authorization)
    assert _pm is not None
    path = None
    if data is not None:
        p = data.get("path")
        if p:
            path = Path(p)
    _pm.handle_backup_reveal_parent_seed(path)
    return {"status": "ok"}


@app.post("/api/v1/change-password")
def change_password(
    data: dict, authorization: str | None = Header(None)
) -> dict[str, str]:
    """Change the master password for the active profile."""
    _check_token(authorization)
    assert _pm is not None
    _pm.change_password(data.get("old", ""), data.get("new", ""))
    return {"status": "ok"}


@app.post("/api/v1/password")
def generate_password(
    data: dict, authorization: str | None = Header(None)
) -> dict[str, str]:
    """Generate a password using optional policy overrides."""
    _check_token(authorization)
    assert _pm is not None
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
    util = UtilityService(_pm)
    password = util.generate_password(length, **kwargs)
    return {"password": password}


@app.post("/api/v1/vault/lock")
def lock_vault(authorization: str | None = Header(None)) -> dict[str, str]:
    """Lock the vault and clear sensitive data from memory."""
    _check_token(authorization)
    assert _pm is not None
    _pm.lock_vault()
    return {"status": "locked"}


@app.post("/api/v1/shutdown")
async def shutdown_server(authorization: str | None = Header(None)) -> dict[str, str]:
    _check_token(authorization)
    asyncio.get_event_loop().call_soon(sys.exit, 0)
    return {"status": "shutting down"}
