from __future__ import annotations

from typing import Optional

import typer

from .common import _get_util_service

app = typer.Typer(help="Utility commands")


@app.command("generate-password")
def generate_password(
    ctx: typer.Context,
    length: int = 24,
    no_special: bool = typer.Option(
        False, "--no-special", help="Exclude special characters", is_flag=True
    ),
    allowed_special_chars: Optional[str] = typer.Option(
        None, "--allowed-special-chars", help="Explicit set of special characters"
    ),
    special_mode: Optional[str] = typer.Option(
        None,
        "--special-mode",
        help="Special character mode",
    ),
    exclude_ambiguous: bool = typer.Option(
        False,
        "--exclude-ambiguous",
        help="Exclude ambiguous characters",
        is_flag=True,
    ),
    min_uppercase: Optional[int] = typer.Option(None, "--min-uppercase"),
    min_lowercase: Optional[int] = typer.Option(None, "--min-lowercase"),
    min_digits: Optional[int] = typer.Option(None, "--min-digits"),
    min_special: Optional[int] = typer.Option(None, "--min-special"),
) -> None:
    """Generate a strong password."""
    service = _get_util_service(ctx)
    kwargs = {}
    if no_special:
        kwargs["include_special_chars"] = False
    if allowed_special_chars is not None:
        kwargs["allowed_special_chars"] = allowed_special_chars
    if special_mode is not None:
        kwargs["special_mode"] = special_mode
    if exclude_ambiguous:
        kwargs["exclude_ambiguous"] = True
    if min_uppercase is not None:
        kwargs["min_uppercase"] = min_uppercase
    if min_lowercase is not None:
        kwargs["min_lowercase"] = min_lowercase
    if min_digits is not None:
        kwargs["min_digits"] = min_digits
    if min_special is not None:
        kwargs["min_special"] = min_special

    password = service.generate_password(length, **kwargs)
    typer.echo(password)


@app.command("verify-checksum")
def verify_checksum(ctx: typer.Context) -> None:
    """Verify the SeedPass script checksum."""
    service = _get_util_service(ctx)
    service.verify_checksum()


@app.command("update-checksum")
def update_checksum(ctx: typer.Context) -> None:
    """Regenerate the script checksum file."""
    service = _get_util_service(ctx)
    service.update_checksum()
