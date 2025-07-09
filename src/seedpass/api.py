"""SeedPass FastAPI server."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
import secrets
from typing import Any, List, Optional

from fastapi import FastAPI, Header, HTTPException, Request
import asyncio
import sys
from fastapi.middleware.cors import CORSMiddleware

from password_manager.manager import PasswordManager


app = FastAPI()

_pm: Optional[PasswordManager] = None
_token: str = ""


def _check_token(auth: str | None) -> None:
    if auth != f"Bearer {_token}":
        raise HTTPException(status_code=401, detail="Unauthorized")


def start_server(fingerprint: str | None = None) -> str:
    """Initialize global state and return the API token.

    Parameters
    ----------
    fingerprint:
        Optional seed profile fingerprint to select before starting the server.
    """
    global _pm, _token
    _pm = PasswordManager()
    if fingerprint:
        _pm.select_fingerprint(fingerprint)
    _token = secrets.token_urlsafe(16)
    print(f"API token: {_token}")
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
        }
        for idx, label, username, url, archived in results
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
        index = _pm.entry_manager.add_entry(
            entry.get("label"),
            int(entry.get("length", 12)),
            entry.get("username"),
            entry.get("url"),
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
            index=entry.get("index"),
            notes=entry.get("notes", ""),
            archived=entry.get("archived", False),
        )
        return {"id": index}

    if etype == "key_value":
        index = _pm.entry_manager.add_key_value(
            entry.get("label"),
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
    _pm.entry_manager.modify_entry(
        entry_id,
        username=entry.get("username"),
        url=entry.get("url"),
        notes=entry.get("notes"),
        label=entry.get("label"),
        period=entry.get("period"),
        digits=entry.get("digits"),
        value=entry.get("value"),
    )
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
    }

    action = mapping.get(key)
    if action is None:
        raise HTTPException(status_code=400, detail="Unknown key")

    if "value" not in data:
        raise HTTPException(status_code=400, detail="Missing value")

    action(data["value"])
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


@app.get("/api/v1/nostr/pubkey")
def get_nostr_pubkey(authorization: str | None = Header(None)) -> Any:
    _check_token(authorization)
    assert _pm is not None
    return {"npub": _pm.nostr_client.key_manager.get_npub()}


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
    return {"status": "ok"}


@app.post("/api/v1/change-password")
def change_password(authorization: str | None = Header(None)) -> dict[str, str]:
    """Change the master password for the active profile."""
    _check_token(authorization)
    assert _pm is not None
    _pm.change_password()
    return {"status": "ok"}


@app.post("/api/v1/shutdown")
async def shutdown_server(authorization: str | None = Header(None)) -> dict[str, str]:
    _check_token(authorization)
    asyncio.get_event_loop().call_soon(sys.exit, 0)
    return {"status": "shutting down"}
