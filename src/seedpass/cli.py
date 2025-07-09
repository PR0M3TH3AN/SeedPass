import typer
from typing import Optional

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

app.add_typer(entry_app, name="entry")
app.add_typer(vault_app, name="vault")
app.add_typer(nostr_app, name="nostr")
app.add_typer(config_app, name="config")
app.add_typer(fingerprint_app, name="fingerprint")
app.add_typer(util_app, name="util")


@app.callback()
def main(ctx: typer.Context, fingerprint: Optional[str] = fingerprint_option) -> None:
    """SeedPass CLI entry point."""
    ctx.obj = {"fingerprint": fingerprint}


@entry_app.command("list")
def entry_list(ctx: typer.Context) -> None:
    """List entries in the vault."""
    typer.echo(f"Listing entries for fingerprint: {ctx.obj.get('fingerprint')}")


@vault_app.command("export")
def vault_export(
    ctx: typer.Context, file: str = typer.Option(..., help="Output file")
) -> None:
    """Export the vault."""
    typer.echo(
        f"Exporting vault for fingerprint {ctx.obj.get('fingerprint')} to {file}"
    )


@nostr_app.command("sync")
def nostr_sync(ctx: typer.Context) -> None:
    """Sync with configured Nostr relays."""
    typer.echo(f"Syncing vault for fingerprint: {ctx.obj.get('fingerprint')}")


@config_app.command("get")
def config_get(ctx: typer.Context, key: str) -> None:
    """Get a configuration value."""
    typer.echo(f"Get config '{key}' for fingerprint: {ctx.obj.get('fingerprint')}")


@fingerprint_app.command("list")
def fingerprint_list(ctx: typer.Context) -> None:
    """List available seed profiles."""
    typer.echo("Listing seed profiles")


@util_app.command("generate-password")
def generate_password(ctx: typer.Context, length: int = 24) -> None:
    """Generate a strong password."""
    typer.echo(f"Generate password of length {length} for {ctx.obj.get('fingerprint')}")
