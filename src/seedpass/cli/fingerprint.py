from __future__ import annotations

import typer

from .common import _get_services, ProfileRemoveRequest, ProfileSwitchRequest

app = typer.Typer(help="Manage seed profiles")


@app.command("list")
def fingerprint_list(ctx: typer.Context) -> None:
    """List available seed profiles."""
    _vault, profile_service, _sync = _get_services(ctx)
    for fp in profile_service.list_profiles():
        typer.echo(fp)


@app.command("add")
def fingerprint_add(ctx: typer.Context) -> None:
    """Create a new seed profile."""
    _vault, profile_service, _sync = _get_services(ctx)
    profile_service.add_profile()


@app.command("remove")
def fingerprint_remove(ctx: typer.Context, fingerprint: str) -> None:
    """Remove a seed profile."""
    _vault, profile_service, _sync = _get_services(ctx)
    profile_service.remove_profile(ProfileRemoveRequest(fingerprint=fingerprint))


@app.command("switch")
def fingerprint_switch(ctx: typer.Context, fingerprint: str) -> None:
    """Switch to another seed profile."""
    _vault, profile_service, _sync = _get_services(ctx)
    password = typer.prompt("Master password", hide_input=True)
    profile_service.switch_profile(
        ProfileSwitchRequest(fingerprint=fingerprint, password=password)
    )
