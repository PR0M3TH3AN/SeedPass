from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import List, Optional

import typer
import click

from .common import _get_entry_service, EntryType
from seedpass.core.entry_types import ALL_ENTRY_TYPES
from utils.clipboard import ClipboardUnavailableError

app = typer.Typer(help="Manage individual entries")


@app.command("list")
def entry_list(
    ctx: typer.Context,
    sort: str = typer.Option(
        "index", "--sort", help="Sort by 'index', 'label', or 'updated'"
    ),
    kind: Optional[str] = typer.Option(
        None,
        "--kind",
        help="Filter by entry type",
        click_type=click.Choice(ALL_ENTRY_TYPES),
    ),
    archived: bool = typer.Option(False, "--archived", help="Include archived"),
) -> None:
    """List entries in the vault."""
    service = _get_entry_service(ctx)
    entries = service.list_entries(
        sort_by=sort,
        filter_kinds=[kind] if kind else None,
        include_archived=archived,
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


@app.command("search")
def entry_search(
    ctx: typer.Context,
    query: str,
    kinds: List[str] = typer.Option(
        None,
        "--kind",
        "-k",
        help="Filter by entry kinds (can be repeated)",
        click_type=click.Choice(ALL_ENTRY_TYPES),
    ),
) -> None:
    """Search entries."""
    service = _get_entry_service(ctx)
    kinds = list(kinds) if kinds else None
    results = service.search_entries(query, kinds=kinds)
    if not results:
        typer.echo("No matching entries found")
        return
    for idx, label, username, url, _arch, etype in results:
        line = f"{idx}: {etype.value.replace('_', ' ').title()} - {label}"
        if username:
            line += f" ({username})"
        if url:
            line += f" {url}"
        typer.echo(line)


@app.command("get")
def entry_get(ctx: typer.Context, query: str) -> None:
    """Retrieve a single entry's secret."""
    service = _get_entry_service(ctx)
    try:
        matches = service.search_entries(query)
        if len(matches) == 0:
            typer.echo("No matching entries found")
            raise typer.Exit(code=1)
        if len(matches) > 1:
            typer.echo("Matches:")
            for idx, label, username, _url, _arch, etype in matches:
                name = f"{idx}: {etype.value.replace('_', ' ').title()} - {label}"
                if username:
                    name += f" ({username})"
                typer.echo(name)
            raise typer.Exit(code=1)

        index = matches[0][0]
        entry = service.retrieve_entry(index)
        etype = entry.get("type", entry.get("kind"))
        if etype == EntryType.PASSWORD.value:
            length = int(entry.get("length", 12))
            password = service.generate_password(length, index)
            typer.echo(password)
        elif etype == EntryType.TOTP.value:
            code = service.get_totp_code(index)
            typer.echo(code)
        else:
            typer.echo("Unsupported entry type")
            raise typer.Exit(code=1)
    except ClipboardUnavailableError as exc:
        typer.echo(
            f"Clipboard unavailable: {exc}\n"
            "Re-run with '--no-clipboard' to print secrets instead.",
            err=True,
        )
        raise typer.Exit(code=1)


@app.command("add")
def entry_add(
    ctx: typer.Context,
    label: str,
    length: int = typer.Option(12, "--length"),
    username: Optional[str] = typer.Option(None, "--username"),
    url: Optional[str] = typer.Option(None, "--url"),
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
    """Add a new password entry and output its index."""
    service = _get_entry_service(ctx)
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

    index = service.add_entry(label, length, username, url, **kwargs)
    typer.echo(str(index))


@app.command("add-totp")
def entry_add_totp(
    ctx: typer.Context,
    label: str,
    index: Optional[int] = typer.Option(None, "--index", help="Derivation index"),
    secret: Optional[str] = typer.Option(None, "--secret", help="Import secret"),
    period: int = typer.Option(30, "--period", help="TOTP period in seconds"),
    digits: int = typer.Option(6, "--digits", help="Number of TOTP digits"),
    deterministic_totp: bool = typer.Option(
        False, "--deterministic-totp", help="Derive secret deterministically"
    ),
) -> None:
    """Add a TOTP entry and output the otpauth URI."""
    service = _get_entry_service(ctx)
    uri = service.add_totp(
        label,
        index=index,
        secret=secret,
        period=period,
        digits=digits,
        deterministic=deterministic_totp,
    )
    typer.echo(uri)


@app.command("add-ssh")
def entry_add_ssh(
    ctx: typer.Context,
    label: str,
    index: Optional[int] = typer.Option(None, "--index", help="Derivation index"),
    notes: str = typer.Option("", "--notes", help="Entry notes"),
) -> None:
    """Add an SSH key entry and output its index."""
    service = _get_entry_service(ctx)
    idx = service.add_ssh_key(
        label,
        index=index,
        notes=notes,
    )
    typer.echo(str(idx))


@app.command("add-pgp")
def entry_add_pgp(
    ctx: typer.Context,
    label: str,
    index: Optional[int] = typer.Option(None, "--index", help="Derivation index"),
    key_type: str = typer.Option("ed25519", "--key-type", help="Key type"),
    user_id: str = typer.Option("", "--user-id", help="User ID"),
    notes: str = typer.Option("", "--notes", help="Entry notes"),
) -> None:
    """Add a PGP key entry and output its index."""
    service = _get_entry_service(ctx)
    idx = service.add_pgp_key(
        label,
        index=index,
        key_type=key_type,
        user_id=user_id,
        notes=notes,
    )
    typer.echo(str(idx))


@app.command("add-nostr")
def entry_add_nostr(
    ctx: typer.Context,
    label: str,
    index: Optional[int] = typer.Option(None, "--index", help="Derivation index"),
    notes: str = typer.Option("", "--notes", help="Entry notes"),
) -> None:
    """Add a Nostr key entry and output its index."""
    service = _get_entry_service(ctx)
    idx = service.add_nostr_key(
        label,
        index=index,
        notes=notes,
    )
    typer.echo(str(idx))


@app.command("add-seed")
def entry_add_seed(
    ctx: typer.Context,
    label: str,
    index: Optional[int] = typer.Option(None, "--index", help="Derivation index"),
    words: int = typer.Option(24, "--words", help="Word count"),
    notes: str = typer.Option("", "--notes", help="Entry notes"),
) -> None:
    """Add a derived seed phrase entry and output its index."""
    service = _get_entry_service(ctx)
    idx = service.add_seed(
        label,
        index=index,
        words=words,
        notes=notes,
    )
    typer.echo(str(idx))


@app.command("add-key-value")
def entry_add_key_value(
    ctx: typer.Context,
    label: str,
    key: str = typer.Option(..., "--key", help="Key name"),
    value: str = typer.Option(..., "--value", help="Stored value"),
    notes: str = typer.Option("", "--notes", help="Entry notes"),
) -> None:
    """Add a key/value entry and output its index."""
    service = _get_entry_service(ctx)
    idx = service.add_key_value(label, key, value, notes=notes)
    typer.echo(str(idx))


@app.command("add-managed-account")
def entry_add_managed_account(
    ctx: typer.Context,
    label: str,
    index: Optional[int] = typer.Option(None, "--index", help="Derivation index"),
    notes: str = typer.Option("", "--notes", help="Entry notes"),
) -> None:
    """Add a managed account seed entry and output its index."""
    service = _get_entry_service(ctx)
    idx = service.add_managed_account(
        label,
        index=index,
        notes=notes,
    )
    typer.echo(str(idx))


@app.command("modify")
def entry_modify(
    ctx: typer.Context,
    entry_id: int,
    label: Optional[str] = typer.Option(None, "--label"),
    username: Optional[str] = typer.Option(None, "--username"),
    url: Optional[str] = typer.Option(None, "--url"),
    notes: Optional[str] = typer.Option(None, "--notes"),
    period: Optional[int] = typer.Option(
        None, "--period", help="TOTP period in seconds"
    ),
    digits: Optional[int] = typer.Option(None, "--digits", help="TOTP digits"),
    key: Optional[str] = typer.Option(None, "--key", help="New key"),
    value: Optional[str] = typer.Option(None, "--value", help="New value"),
) -> None:
    """Modify an existing entry."""
    service = _get_entry_service(ctx)
    try:
        service.modify_entry(
            entry_id,
            username=username,
            url=url,
            notes=notes,
            label=label,
            period=period,
            digits=digits,
            key=key,
            value=value,
        )
    except ValueError as e:
        typer.echo(str(e))
        sys.stdout.flush()
        raise typer.Exit(code=1)


@app.command("archive")
def entry_archive(ctx: typer.Context, entry_id: int) -> None:
    """Archive an entry."""
    service = _get_entry_service(ctx)
    service.archive_entry(entry_id)
    typer.echo(str(entry_id))


@app.command("unarchive")
def entry_unarchive(ctx: typer.Context, entry_id: int) -> None:
    """Restore an archived entry."""
    service = _get_entry_service(ctx)
    service.restore_entry(entry_id)
    typer.echo(str(entry_id))


@app.command("totp-codes")
def entry_totp_codes(ctx: typer.Context) -> None:
    """Display all current TOTP codes."""
    service = _get_entry_service(ctx)
    service.display_totp_codes()


@app.command("export-totp")
def entry_export_totp(
    ctx: typer.Context, file: str = typer.Option(..., help="Output file")
) -> None:
    """Export all TOTP secrets to a JSON file."""
    service = _get_entry_service(ctx)
    data = service.export_totp_entries()
    Path(file).write_text(json.dumps(data, indent=2))
    typer.echo(str(file))
