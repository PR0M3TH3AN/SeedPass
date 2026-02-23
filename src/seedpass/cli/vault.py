from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer

from .common import (
    _get_services,
    ChangePasswordRequest,
    UnlockRequest,
    BackupParentSeedRequest,
)

app = typer.Typer(help="Manage the entire vault")


@app.command("export")
def vault_export(
    ctx: typer.Context, file: str = typer.Option(..., help="Output file")
) -> None:
    """Export the vault profile to an encrypted file."""
    vault_service, _profile, _sync = _get_services(ctx)
    data = vault_service.export_profile()
    Path(file).write_bytes(data)
    typer.echo(str(file))


@app.command("import")
def vault_import(
    ctx: typer.Context, file: str = typer.Option(..., help="Input file")
) -> None:
    """Import a vault profile from an encrypted file."""
    vault_service, _profile, _sync = _get_services(ctx)
    data = Path(file).read_bytes()
    vault_service.import_profile(data)
    typer.echo(str(file))


@app.command("change-password")
def vault_change_password(ctx: typer.Context) -> None:
    """Change the master password used for encryption."""
    vault_service, _profile, _sync = _get_services(ctx)
    old_pw = typer.prompt("Current password", hide_input=True)
    new_pw = typer.prompt("New password", hide_input=True, confirmation_prompt=True)
    try:
        vault_service.change_password(
            ChangePasswordRequest(old_password=old_pw, new_password=new_pw)
        )
    except Exception as exc:  # pragma: no cover - pass through errors
        typer.echo(f"Error: {exc}")
        raise typer.Exit(code=1)
    typer.echo("Password updated")


@app.command("unlock")
def vault_unlock(ctx: typer.Context) -> None:
    """Unlock the vault for the active profile."""
    vault_service, _profile, _sync = _get_services(ctx)
    password = typer.prompt("Master password", hide_input=True)
    try:
        resp = vault_service.unlock(UnlockRequest(password=password))
    except Exception as exc:  # pragma: no cover - pass through errors
        typer.echo(f"Error: {exc}")
        raise typer.Exit(code=1)
    typer.echo(f"Unlocked in {resp.duration:.2f}s")


@app.command("lock")
def vault_lock(ctx: typer.Context) -> None:
    """Lock the vault and clear sensitive data from memory."""
    vault_service, _profile, _sync = _get_services(ctx)
    vault_service.lock()
    typer.echo("locked")


@app.command("stats")
def vault_stats(ctx: typer.Context) -> None:
    """Display statistics about the current seed profile."""
    vault_service, _profile, _sync = _get_services(ctx)
    stats = vault_service.stats()
    typer.echo(json.dumps(stats, indent=2))


@app.command("reveal-parent-seed")
def vault_reveal_parent_seed(
    ctx: typer.Context,
    file: Optional[str] = typer.Option(
        None, "--file", help="Save encrypted seed to this path"
    ),
) -> None:
    """Display the parent seed and optionally write an encrypted backup file."""
    vault_service, _profile, _sync = _get_services(ctx)
    password = typer.prompt("Master password", hide_input=True)
    vault_service.backup_parent_seed(
        BackupParentSeedRequest(path=Path(file) if file else None, password=password)
    )
