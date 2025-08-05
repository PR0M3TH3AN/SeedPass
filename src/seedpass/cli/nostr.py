from __future__ import annotations

import typer

from .common import _get_services, _get_nostr_service


app = typer.Typer(help="Interact with Nostr relays")


@app.command("sync")
def nostr_sync(ctx: typer.Context) -> None:
    """Sync with configured Nostr relays."""
    _vault, _profile, sync_service = _get_services(ctx)
    model = sync_service.sync()
    if model:
        typer.echo("Event IDs:")
        typer.echo(f"- manifest: {model.manifest_id}")
        for cid in model.chunk_ids:
            typer.echo(f"- chunk: {cid}")
        for did in model.delta_ids:
            typer.echo(f"- delta: {did}")
    else:
        typer.echo("Error: Failed to sync vault")


@app.command("get-pubkey")
def nostr_get_pubkey(ctx: typer.Context) -> None:
    """Display the active profile's npub."""
    service = _get_nostr_service(ctx)
    npub = service.get_pubkey()
    typer.echo(npub)


@app.command("list-relays")
def nostr_list_relays(ctx: typer.Context) -> None:
    """Display configured Nostr relays."""
    service = _get_nostr_service(ctx)
    relays = service.list_relays()
    for i, r in enumerate(relays, 1):
        typer.echo(f"{i}: {r}")


@app.command("add-relay")
def nostr_add_relay(ctx: typer.Context, url: str) -> None:
    """Add a relay URL."""
    service = _get_nostr_service(ctx)
    try:
        service.add_relay(url)
    except Exception as exc:  # pragma: no cover - pass through errors
        typer.echo(f"Error: {exc}")
        raise typer.Exit(code=1)
    typer.echo("Added")


@app.command("remove-relay")
def nostr_remove_relay(ctx: typer.Context, idx: int) -> None:
    """Remove a relay by index (1-based)."""
    service = _get_nostr_service(ctx)
    try:
        service.remove_relay(idx)
    except Exception as exc:  # pragma: no cover - pass through errors
        typer.echo(f"Error: {exc}")
        raise typer.Exit(code=1)
    typer.echo("Removed")
