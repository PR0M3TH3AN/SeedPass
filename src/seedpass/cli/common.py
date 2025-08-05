from __future__ import annotations

import typer

from seedpass.core.manager import PasswordManager
from seedpass.core.entry_types import EntryType
from seedpass.core.api import (
    VaultService,
    ProfileService,
    SyncService,
    EntryService,
    ConfigService,
    UtilityService,
    NostrService,
    ChangePasswordRequest,
    UnlockRequest,
    BackupParentSeedRequest,
    ProfileSwitchRequest,
    ProfileRemoveRequest,
)


def _get_pm(ctx: typer.Context) -> PasswordManager:
    """Return a PasswordManager optionally selecting a fingerprint."""
    fp = ctx.obj.get("fingerprint")
    if fp is None:
        pm = PasswordManager()
    else:
        pm = PasswordManager(fingerprint=fp)
    return pm


def _get_services(
    ctx: typer.Context,
) -> tuple[VaultService, ProfileService, SyncService]:
    """Return service layer instances for the current context."""

    pm = _get_pm(ctx)
    return VaultService(pm), ProfileService(pm), SyncService(pm)


def _get_entry_service(ctx: typer.Context) -> EntryService:
    pm = _get_pm(ctx)
    return EntryService(pm)


def _get_config_service(ctx: typer.Context) -> ConfigService:
    pm = _get_pm(ctx)
    return ConfigService(pm)


def _get_util_service(ctx: typer.Context) -> UtilityService:
    pm = _get_pm(ctx)
    return UtilityService(pm)


def _get_nostr_service(ctx: typer.Context) -> NostrService:
    pm = _get_pm(ctx)
    return NostrService(pm)
