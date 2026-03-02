from __future__ import annotations

import json
from typing import Optional

import typer
import click

from .common import _get_pm
from seedpass.core.api import SemanticIndexService
from seedpass.core.entry_types import ALL_ENTRY_TYPES

app = typer.Typer(help="Manage local semantic vector index and search")
SEARCH_MODES = ["keyword", "hybrid", "semantic"]


def _get_semantic_service(ctx: typer.Context) -> SemanticIndexService:
    return SemanticIndexService(_get_pm(ctx))


@app.command("status")
def semantic_status(ctx: typer.Context) -> None:
    """Show semantic index status for the active profile."""
    service = _get_semantic_service(ctx)
    payload = service.status()
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


@app.command("enable")
def semantic_enable(ctx: typer.Context) -> None:
    """Enable semantic index for this profile."""
    service = _get_semantic_service(ctx)
    payload = service.set_enabled(True)
    typer.echo(
        f"semantic index enabled (built={payload.get('built', False)}, records={payload.get('records', 0)})"
    )


@app.command("disable")
def semantic_disable(ctx: typer.Context) -> None:
    """Disable semantic index for this profile."""
    service = _get_semantic_service(ctx)
    payload = service.set_enabled(False)
    typer.echo(
        f"semantic index disabled (built={payload.get('built', False)}, records={payload.get('records', 0)})"
    )


@app.command("build")
def semantic_build(ctx: typer.Context) -> None:
    """Build semantic index incrementally from current entries."""
    service = _get_semantic_service(ctx)
    payload = service.build()
    typer.echo(
        f"semantic index built (records={payload.get('records', 0)}, enabled={payload.get('enabled', False)})"
    )


@app.command("rebuild")
def semantic_rebuild(ctx: typer.Context) -> None:
    """Rebuild semantic index from scratch."""
    service = _get_semantic_service(ctx)
    payload = service.rebuild()
    typer.echo(
        f"semantic index rebuilt (records={payload.get('records', 0)}, enabled={payload.get('enabled', False)})"
    )


@app.command("search")
def semantic_search(
    ctx: typer.Context,
    query: str,
    k: int = typer.Option(10, "--k", help="Max results"),
    kind: Optional[str] = typer.Option(
        None,
        "--kind",
        help="Restrict to entry kind",
        click_type=click.Choice(ALL_ENTRY_TYPES),
    ),
    mode: Optional[str] = typer.Option(
        None,
        "--mode",
        help="Search mode override",
        click_type=click.Choice(SEARCH_MODES),
    ),
    as_json: bool = typer.Option(False, "--json", help="Emit JSON output"),
) -> None:
    """Run semantic search over locally indexed KB content."""
    service = _get_semantic_service(ctx)
    results = service.search(query, k=max(1, int(k)), kind=kind, mode=mode)
    if as_json:
        typer.echo(json.dumps(results, indent=2, sort_keys=True))
        return
    if not results:
        typer.echo("No semantic matches")
        return
    for item in results:
        entry_id = int(item.get("entry_id", 0))
        label = str(item.get("label", ""))
        entry_kind = str(item.get("kind", ""))
        score = float(item.get("score", 0.0))
        excerpt = str(item.get("excerpt", ""))
        typer.echo(f"{entry_id}: [{entry_kind}] {label} (score={score:.3f})")
        if excerpt:
            typer.echo(f"  {excerpt}")


@app.command("config")
def semantic_config(
    ctx: typer.Context,
    enabled: Optional[str] = typer.Option(
        None,
        "--enabled",
        help="Enable or disable semantic index for this profile",
        click_type=click.Choice(["true", "false"]),
    ),
    mode: Optional[str] = typer.Option(
        None,
        "--mode",
        help="Default semantic search mode",
        click_type=click.Choice(SEARCH_MODES),
    ),
) -> None:
    """Configure semantic index behavior for the active profile."""
    if enabled is None and mode is None:
        typer.echo("Provide at least one option: --enabled or --mode")
        raise typer.Exit(code=1)
    service = _get_semantic_service(ctx)
    if enabled is not None:
        service.set_enabled(enabled == "true")
    if mode is not None:
        service.set_mode(mode)
    payload = service.status()
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))
