"""SeedPass FastAPI server."""

from __future__ import annotations

import os
import secrets
from typing import Any, List, Optional

from fastapi import FastAPI, Header, HTTPException
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
) -> dict[str, int]:
    """Create a new password entry."""
    _check_token(authorization)
    assert _pm is not None
    index = _pm.entry_manager.add_entry(
        entry.get("label"),
        int(entry.get("length", 12)),
        entry.get("username"),
        entry.get("url"),
    )
    return {"id": index}


@app.put("/api/v1/entry/{entry_id}")
def update_entry(
    entry_id: int,
    entry: dict,
    authorization: str | None = Header(None),
) -> dict[str, str]:
    """Update an existing entry."""
    _check_token(authorization)
    assert _pm is not None
    _pm.entry_manager.modify_entry(
        entry_id,
        username=entry.get("username"),
        url=entry.get("url"),
        notes=entry.get("notes"),
        label=entry.get("label"),
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


@app.get("/api/v1/fingerprint")
def list_fingerprints(authorization: str | None = Header(None)) -> List[str]:
    _check_token(authorization)
    assert _pm is not None
    return _pm.fingerprint_manager.list_fingerprints()


@app.get("/api/v1/nostr/pubkey")
def get_nostr_pubkey(authorization: str | None = Header(None)) -> Any:
    _check_token(authorization)
    assert _pm is not None
    return {"npub": _pm.nostr_client.key_manager.get_npub()}


@app.post("/api/v1/shutdown")
async def shutdown_server(authorization: str | None = Header(None)) -> dict[str, str]:
    _check_token(authorization)
    asyncio.get_event_loop().call_soon(sys.exit, 0)
    return {"status": "shutting down"}
