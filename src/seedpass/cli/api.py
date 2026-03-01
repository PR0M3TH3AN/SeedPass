from __future__ import annotations

from typing import Optional

import click
import typer
import uvicorn

from .. import api as api_module
from seedpass.core.auth_broker import AuthBrokerError, resolve_password as resolve_broker_password

app = typer.Typer(help="Run the API server")


@app.command("start")
def api_start(
    ctx: typer.Context,
    host: str = "127.0.0.1",
    port: int = 8000,
    unlock: bool = typer.Option(
        False, "--unlock", help="Unlock vault during startup using the selected auth broker"
    ),
    auth_broker: str = typer.Option(
        "prompt",
        "--auth-broker",
        help="Password source when --unlock is used (prompt|env|keyring|command)",
        click_type=click.Choice(["prompt", "env", "keyring", "command"], case_sensitive=False),
    ),
    password_env: str = typer.Option(
        "SEEDPASS_PASSWORD", "--password-env", help="Env var used when --auth-broker=env"
    ),
    broker_service: str = typer.Option(
        "seedpass",
        "--broker-service",
        help="Keyring service name when --auth-broker=keyring",
    ),
    broker_account: Optional[str] = typer.Option(
        None,
        "--broker-account",
        help="Keyring account (defaults to active fingerprint when available)",
    ),
    broker_command: Optional[str] = typer.Option(
        None,
        "--broker-command",
        help="Command that prints password to stdout for --auth-broker=command",
    ),
) -> None:
    """Start the SeedPass API server."""
    unlock_password: str | None = None
    if unlock:
        if auth_broker.lower() == "prompt":
            unlock_password = typer.prompt("Master password", hide_input=True)
        else:
            account = broker_account or str((ctx.obj or {}).get("fingerprint") or "default")
            try:
                unlock_password = resolve_broker_password(
                    broker=auth_broker,
                    password_env=password_env,
                    broker_service=broker_service,
                    broker_account=account,
                    broker_command=broker_command,
                )
            except AuthBrokerError as exc:
                raise typer.BadParameter(str(exc)) from exc
    token = api_module.start_server(ctx.obj.get("fingerprint"), unlock_password)
    typer.echo(
        f"API token: {token}\nWARNING: Store this token securely; it cannot be recovered."
    )
    uvicorn.run(api_module.app, host=host, port=port)


@app.command("stop")
def api_stop(
    token: str = typer.Option(..., help="API token"),
    host: str = "127.0.0.1",
    port: int = 8000,
) -> None:
    """Stop the SeedPass API server."""
    import requests

    try:
        requests.post(
            f"http://{host}:{port}/api/v1/shutdown",
            headers={"Authorization": f"Bearer {token}"},
            timeout=2,
        )
    except Exception as exc:  # pragma: no cover - best effort
        typer.echo(f"Failed to stop server: {exc}")
