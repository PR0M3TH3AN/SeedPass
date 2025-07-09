from pathlib import Path
from typing import Optional

import typer

from password_manager.manager import PasswordManager
from password_manager.entry_types import EntryType
import uvicorn
from . import api as api_module

app = typer.Typer(help="SeedPass command line interface")

# Global option shared across all commands
fingerprint_option = typer.Option(
    None,
    "--fingerprint",
    "-f",
    help="Specify which seed profile to use",
)

# Sub command groups
entry_app = typer.Typer(help="Manage individual entries")
vault_app = typer.Typer(help="Manage the entire vault")
nostr_app = typer.Typer(help="Interact with Nostr relays")
config_app = typer.Typer(help="Manage configuration values")
fingerprint_app = typer.Typer(help="Manage seed profiles")
util_app = typer.Typer(help="Utility commands")
api_app = typer.Typer(help="Run the API server")

app.add_typer(entry_app, name="entry")
app.add_typer(vault_app, name="vault")
app.add_typer(nostr_app, name="nostr")
app.add_typer(config_app, name="config")
app.add_typer(fingerprint_app, name="fingerprint")
app.add_typer(util_app, name="util")
app.add_typer(api_app, name="api")


def _get_pm(ctx: typer.Context) -> PasswordManager:
    """Return a PasswordManager optionally selecting a fingerprint."""
    pm = PasswordManager()
    fp = ctx.obj.get("fingerprint")
    if fp:
        # `select_fingerprint` will initialize managers
        pm.select_fingerprint(fp)
    return pm


@app.callback()
def main(ctx: typer.Context, fingerprint: Optional[str] = fingerprint_option) -> None:
    """SeedPass CLI entry point."""
    ctx.obj = {"fingerprint": fingerprint}


@entry_app.command("list")
def entry_list(
    ctx: typer.Context,
    sort: str = typer.Option(
        "index", "--sort", help="Sort by 'index', 'label', or 'username'"
    ),
    kind: Optional[str] = typer.Option(None, "--kind", help="Filter by entry type"),
    archived: bool = typer.Option(False, "--archived", help="Include archived"),
) -> None:
    """List entries in the vault."""
    pm = _get_pm(ctx)
    entries = pm.entry_manager.list_entries(
        sort_by=sort, filter_kind=kind, include_archived=archived
    )
    for idx, label, username, url, is_archived in entries:
        line = f"{idx}: {label}"
        if username:
            line += f" ({username})"
        if url:
            line += f" {url}"
        if is_archived:
            line += " [archived]"
        typer.echo(line)


@entry_app.command("search")
def entry_search(ctx: typer.Context, query: str) -> None:
    """Search entries."""
    pm = _get_pm(ctx)
    results = pm.entry_manager.search_entries(query)
    if not results:
        typer.echo("No matching entries found")
        return
    for idx, label, username, url, _arch in results:
        line = f"{idx}: {label}"
        if username:
            line += f" ({username})"
        if url:
            line += f" {url}"
        typer.echo(line)


@entry_app.command("get")
def entry_get(ctx: typer.Context, query: str) -> None:
    """Retrieve a single entry's secret."""
    pm = _get_pm(ctx)
    matches = pm.entry_manager.search_entries(query)
    if len(matches) == 0:
        typer.echo("No matching entries found")
        raise typer.Exit(code=1)
    if len(matches) > 1:
        typer.echo("Matches:")
        for idx, label, username, _url, _arch in matches:
            name = f"{idx}: {label}"
            if username:
                name += f" ({username})"
            typer.echo(name)
        raise typer.Exit(code=1)

    index = matches[0][0]
    entry = pm.entry_manager.retrieve_entry(index)
    etype = entry.get("type", entry.get("kind"))
    if etype == EntryType.PASSWORD.value:
        length = int(entry.get("length", 12))
        password = pm.password_generator.generate_password(length, index)
        typer.echo(password)
    elif etype == EntryType.TOTP.value:
        code = pm.entry_manager.get_totp_code(index, pm.parent_seed)
        typer.echo(code)
    else:
        typer.echo("Unsupported entry type")
        raise typer.Exit(code=1)


@vault_app.command("export")
def vault_export(
    ctx: typer.Context, file: str = typer.Option(..., help="Output file")
) -> None:
    """Export the vault."""
    pm = _get_pm(ctx)
    pm.handle_export_database(Path(file))
    typer.echo(str(file))


@nostr_app.command("sync")
def nostr_sync(ctx: typer.Context) -> None:
    """Sync with configured Nostr relays."""
    typer.echo(f"Syncing vault for fingerprint: {ctx.obj.get('fingerprint')}")


@nostr_app.command("get-pubkey")
def nostr_get_pubkey(ctx: typer.Context) -> None:
    """Display the active profile's npub."""
    pm = _get_pm(ctx)
    npub = pm.nostr_client.key_manager.get_npub()
    typer.echo(npub)


@config_app.command("get")
def config_get(ctx: typer.Context, key: str) -> None:
    """Get a configuration value."""
    pm = _get_pm(ctx)
    value = pm.config_manager.load_config(require_pin=False).get(key)
    if value is None:
        typer.echo("Key not found")
    else:
        typer.echo(str(value))


@fingerprint_app.command("list")
def fingerprint_list(ctx: typer.Context) -> None:
    """List available seed profiles."""
    pm = _get_pm(ctx)
    for fp in pm.fingerprint_manager.list_fingerprints():
        typer.echo(fp)


@util_app.command("generate-password")
def generate_password(ctx: typer.Context, length: int = 24) -> None:
    """Generate a strong password."""
    typer.echo(f"Generate password of length {length} for {ctx.obj.get('fingerprint')}")


@api_app.command("start")
def api_start(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Start the SeedPass API server."""
    token = api_module.start_server()
    typer.echo(f"API token: {token}")
    uvicorn.run(api_module.app, host=host, port=port)


@api_app.command("stop")
def api_stop(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Stop the SeedPass API server."""
    import requests

    try:
        requests.post(
            f"http://{host}:{port}/api/v1/shutdown",
            headers={"Authorization": f"Bearer {api_module._token}"},
            timeout=2,
        )
    except Exception as exc:  # pragma: no cover - best effort
        typer.echo(f"Failed to stop server: {exc}")
