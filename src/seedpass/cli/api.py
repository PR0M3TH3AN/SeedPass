from __future__ import annotations

import typer
import uvicorn

from .. import api as api_module

app = typer.Typer(help="Run the API server")


@app.command("start")
def api_start(ctx: typer.Context, host: str = "127.0.0.1", port: int = 8000) -> None:
    """Start the SeedPass API server."""
    token = api_module.start_server(ctx.obj.get("fingerprint"))
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
