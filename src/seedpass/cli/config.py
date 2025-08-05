from __future__ import annotations

import typer

from .common import _get_config_service


app = typer.Typer(help="Get or set configuration values")


@app.command("get")
def config_get(ctx: typer.Context, key: str) -> None:
    """Get a configuration value."""
    service = _get_config_service(ctx)
    value = service.get(key)
    if value is None:
        typer.echo("Key not found")
    else:
        typer.echo(str(value))


@app.command("set")
def config_set(ctx: typer.Context, key: str, value: str) -> None:
    """Set a configuration value."""
    service = _get_config_service(ctx)

    try:
        val = (
            [r.strip() for r in value.split(",") if r.strip()]
            if key == "relays"
            else value
        )
        service.set(key, val)
    except KeyError:
        typer.echo("Unknown key")
        raise typer.Exit(code=1)
    except Exception as exc:  # pragma: no cover - pass through errors
        typer.echo(f"Error: {exc}")
        raise typer.Exit(code=1)

    typer.echo("Updated")


@app.command("toggle-secret-mode")
def config_toggle_secret_mode(ctx: typer.Context) -> None:
    """Interactively enable or disable secret mode.

    When enabled, newly generated and retrieved passwords are copied to the
    clipboard instead of printed to the screen.
    """
    service = _get_config_service(ctx)
    try:
        enabled = service.get_secret_mode_enabled()
        delay = service.get_clipboard_clear_delay()
    except Exception as exc:  # pragma: no cover - pass through errors
        typer.echo(f"Error loading settings: {exc}")
        raise typer.Exit(code=1)

    typer.echo(f"Secret mode is currently {'ON' if enabled else 'OFF'}")
    choice = (
        typer.prompt(
            "Enable secret mode? (y/n, blank to keep)", default="", show_default=False
        )
        .strip()
        .lower()
    )
    if choice in ("y", "yes"):
        enabled = True
    elif choice in ("n", "no"):
        enabled = False

    inp = typer.prompt(
        f"Clipboard clear delay in seconds [{delay}]", default="", show_default=False
    ).strip()
    if inp:
        try:
            delay = int(inp)
            if delay <= 0:
                typer.echo("Delay must be positive")
                raise typer.Exit(code=1)
        except ValueError:
            typer.echo("Invalid number")
            raise typer.Exit(code=1)

    try:
        service.set_secret_mode(enabled, delay)
    except Exception as exc:  # pragma: no cover - pass through errors
        typer.echo(f"Error: {exc}")
        raise typer.Exit(code=1)

    status = "enabled" if enabled else "disabled"
    typer.echo(f"Secret mode {status}.")


@app.command("toggle-offline")
def config_toggle_offline(ctx: typer.Context) -> None:
    """Enable or disable offline mode."""
    service = _get_config_service(ctx)
    try:
        enabled = service.get_offline_mode()
    except Exception as exc:  # pragma: no cover - pass through errors
        typer.echo(f"Error loading settings: {exc}")
        raise typer.Exit(code=1)

    typer.echo(f"Offline mode is currently {'ON' if enabled else 'OFF'}")
    choice = (
        typer.prompt(
            "Enable offline mode? (y/n, blank to keep)", default="", show_default=False
        )
        .strip()
        .lower()
    )
    if choice in ("y", "yes"):
        enabled = True
    elif choice in ("n", "no"):
        enabled = False

    try:
        service.set_offline_mode(enabled)
    except Exception as exc:  # pragma: no cover - pass through errors
        typer.echo(f"Error: {exc}")
        raise typer.Exit(code=1)

    status = "enabled" if enabled else "disabled"
    typer.echo(f"Offline mode {status}.")
