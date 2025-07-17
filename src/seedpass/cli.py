from pathlib import Path
from typing import Optional
import json

import typer

from seedpass.core.manager import PasswordManager
from seedpass.core.entry_types import EntryType
import uvicorn
from . import api as api_module

import importlib

app = typer.Typer(
    help="SeedPass command line interface",
    invoke_without_command=True,
)

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
config_app = typer.Typer(help="Get or set configuration values")
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
    fp = ctx.obj.get("fingerprint")
    if fp is None:
        pm = PasswordManager()
    else:
        pm = PasswordManager(fingerprint=fp)
    return pm


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context, fingerprint: Optional[str] = fingerprint_option) -> None:
    """SeedPass CLI entry point.

    When called without a subcommand this launches the interactive TUI.
    """
    ctx.obj = {"fingerprint": fingerprint}
    if ctx.invoked_subcommand is None:
        tui = importlib.import_module("main")
        raise typer.Exit(tui.main(fingerprint=fingerprint))


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


@entry_app.command("add")
def entry_add(
    ctx: typer.Context,
    label: str,
    length: int = typer.Option(12, "--length"),
    username: Optional[str] = typer.Option(None, "--username"),
    url: Optional[str] = typer.Option(None, "--url"),
) -> None:
    """Add a new password entry and output its index."""
    pm = _get_pm(ctx)
    index = pm.entry_manager.add_entry(label, length, username, url)
    typer.echo(str(index))
    pm.sync_vault()


@entry_app.command("add-totp")
def entry_add_totp(
    ctx: typer.Context,
    label: str,
    index: Optional[int] = typer.Option(None, "--index", help="Derivation index"),
    secret: Optional[str] = typer.Option(None, "--secret", help="Import secret"),
    period: int = typer.Option(30, "--period", help="TOTP period in seconds"),
    digits: int = typer.Option(6, "--digits", help="Number of TOTP digits"),
) -> None:
    """Add a TOTP entry and output the otpauth URI."""
    pm = _get_pm(ctx)
    uri = pm.entry_manager.add_totp(
        label,
        pm.parent_seed,
        index=index,
        secret=secret,
        period=period,
        digits=digits,
    )
    typer.echo(uri)
    pm.sync_vault()


@entry_app.command("add-ssh")
def entry_add_ssh(
    ctx: typer.Context,
    label: str,
    index: Optional[int] = typer.Option(None, "--index", help="Derivation index"),
    notes: str = typer.Option("", "--notes", help="Entry notes"),
) -> None:
    """Add an SSH key entry and output its index."""
    pm = _get_pm(ctx)
    idx = pm.entry_manager.add_ssh_key(
        label,
        pm.parent_seed,
        index=index,
        notes=notes,
    )
    typer.echo(str(idx))
    pm.sync_vault()


@entry_app.command("add-pgp")
def entry_add_pgp(
    ctx: typer.Context,
    label: str,
    index: Optional[int] = typer.Option(None, "--index", help="Derivation index"),
    key_type: str = typer.Option("ed25519", "--key-type", help="Key type"),
    user_id: str = typer.Option("", "--user-id", help="User ID"),
    notes: str = typer.Option("", "--notes", help="Entry notes"),
) -> None:
    """Add a PGP key entry and output its index."""
    pm = _get_pm(ctx)
    idx = pm.entry_manager.add_pgp_key(
        label,
        pm.parent_seed,
        index=index,
        key_type=key_type,
        user_id=user_id,
        notes=notes,
    )
    typer.echo(str(idx))
    pm.sync_vault()


@entry_app.command("add-nostr")
def entry_add_nostr(
    ctx: typer.Context,
    label: str,
    index: Optional[int] = typer.Option(None, "--index", help="Derivation index"),
    notes: str = typer.Option("", "--notes", help="Entry notes"),
) -> None:
    """Add a Nostr key entry and output its index."""
    pm = _get_pm(ctx)
    idx = pm.entry_manager.add_nostr_key(
        label,
        index=index,
        notes=notes,
    )
    typer.echo(str(idx))
    pm.sync_vault()


@entry_app.command("add-seed")
def entry_add_seed(
    ctx: typer.Context,
    label: str,
    index: Optional[int] = typer.Option(None, "--index", help="Derivation index"),
    words: int = typer.Option(24, "--words", help="Word count"),
    notes: str = typer.Option("", "--notes", help="Entry notes"),
) -> None:
    """Add a derived seed phrase entry and output its index."""
    pm = _get_pm(ctx)
    idx = pm.entry_manager.add_seed(
        label,
        pm.parent_seed,
        index=index,
        words_num=words,
        notes=notes,
    )
    typer.echo(str(idx))
    pm.sync_vault()


@entry_app.command("add-key-value")
def entry_add_key_value(
    ctx: typer.Context,
    label: str,
    value: str = typer.Option(..., "--value", help="Stored value"),
    notes: str = typer.Option("", "--notes", help="Entry notes"),
) -> None:
    """Add a key/value entry and output its index."""
    pm = _get_pm(ctx)
    idx = pm.entry_manager.add_key_value(label, value, notes=notes)
    typer.echo(str(idx))
    pm.sync_vault()


@entry_app.command("add-managed-account")
def entry_add_managed_account(
    ctx: typer.Context,
    label: str,
    index: Optional[int] = typer.Option(None, "--index", help="Derivation index"),
    notes: str = typer.Option("", "--notes", help="Entry notes"),
) -> None:
    """Add a managed account seed entry and output its index."""
    pm = _get_pm(ctx)
    idx = pm.entry_manager.add_managed_account(
        label,
        pm.parent_seed,
        index=index,
        notes=notes,
    )
    typer.echo(str(idx))
    pm.sync_vault()


@entry_app.command("modify")
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
    value: Optional[str] = typer.Option(None, "--value", help="New value"),
) -> None:
    """Modify an existing entry."""
    pm = _get_pm(ctx)
    try:
        pm.entry_manager.modify_entry(
            entry_id,
            username=username,
            url=url,
            notes=notes,
            label=label,
            period=period,
            digits=digits,
            value=value,
        )
    except ValueError as e:
        typer.echo(str(e))
        raise typer.Exit(code=1)
    pm.sync_vault()


@entry_app.command("archive")
def entry_archive(ctx: typer.Context, entry_id: int) -> None:
    """Archive an entry."""
    pm = _get_pm(ctx)
    pm.entry_manager.archive_entry(entry_id)
    typer.echo(str(entry_id))
    pm.sync_vault()


@entry_app.command("unarchive")
def entry_unarchive(ctx: typer.Context, entry_id: int) -> None:
    """Restore an archived entry."""
    pm = _get_pm(ctx)
    pm.entry_manager.restore_entry(entry_id)
    typer.echo(str(entry_id))
    pm.sync_vault()


@entry_app.command("totp-codes")
def entry_totp_codes(ctx: typer.Context) -> None:
    """Display all current TOTP codes."""
    pm = _get_pm(ctx)
    pm.handle_display_totp_codes()


@entry_app.command("export-totp")
def entry_export_totp(
    ctx: typer.Context, file: str = typer.Option(..., help="Output file")
) -> None:
    """Export all TOTP secrets to a JSON file."""
    pm = _get_pm(ctx)
    data = pm.entry_manager.export_totp_entries(pm.parent_seed)
    Path(file).write_text(json.dumps(data, indent=2))
    typer.echo(str(file))


@vault_app.command("export")
def vault_export(
    ctx: typer.Context, file: str = typer.Option(..., help="Output file")
) -> None:
    """Export the vault."""
    pm = _get_pm(ctx)
    pm.handle_export_database(Path(file))
    typer.echo(str(file))


@vault_app.command("import")
def vault_import(
    ctx: typer.Context, file: str = typer.Option(..., help="Input file")
) -> None:
    """Import a vault from an encrypted JSON file."""
    pm = _get_pm(ctx)
    pm.handle_import_database(Path(file))
    pm.sync_vault()
    typer.echo(str(file))


@vault_app.command("change-password")
def vault_change_password(ctx: typer.Context) -> None:
    """Change the master password used for encryption."""
    pm = _get_pm(ctx)
    pm.change_password()


@vault_app.command("lock")
def vault_lock(ctx: typer.Context) -> None:
    """Lock the vault and clear sensitive data from memory."""
    pm = _get_pm(ctx)
    pm.lock_vault()
    typer.echo("locked")


@vault_app.command("stats")
def vault_stats(ctx: typer.Context) -> None:
    """Display statistics about the current seed profile."""
    pm = _get_pm(ctx)
    stats = pm.get_profile_stats()
    typer.echo(json.dumps(stats, indent=2))


@vault_app.command("reveal-parent-seed")
def vault_reveal_parent_seed(
    ctx: typer.Context,
    file: Optional[str] = typer.Option(
        None, "--file", help="Save encrypted seed to this path"
    ),
) -> None:
    """Display the parent seed and optionally write an encrypted backup file."""
    pm = _get_pm(ctx)
    pm.handle_backup_reveal_parent_seed(Path(file) if file else None)


@nostr_app.command("sync")
def nostr_sync(ctx: typer.Context) -> None:
    """Sync with configured Nostr relays."""
    pm = _get_pm(ctx)
    result = pm.sync_vault()
    if result:
        typer.echo("Event IDs:")
        typer.echo(f"- manifest: {result['manifest_id']}")
        for cid in result["chunk_ids"]:
            typer.echo(f"- chunk: {cid}")
        for did in result["delta_ids"]:
            typer.echo(f"- delta: {did}")
    else:
        typer.echo("Error: Failed to sync vault")


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


@config_app.command("set")
def config_set(ctx: typer.Context, key: str, value: str) -> None:
    """Set a configuration value."""
    pm = _get_pm(ctx)
    cfg = pm.config_manager

    mapping = {
        "inactivity_timeout": lambda v: cfg.set_inactivity_timeout(float(v)),
        "secret_mode_enabled": lambda v: cfg.set_secret_mode_enabled(
            v.lower() in ("1", "true", "yes", "y", "on")
        ),
        "clipboard_clear_delay": lambda v: cfg.set_clipboard_clear_delay(int(v)),
        "additional_backup_path": lambda v: cfg.set_additional_backup_path(v or None),
        "relays": lambda v: cfg.set_relays(
            [r.strip() for r in v.split(",") if r.strip()], require_pin=False
        ),
        "kdf_iterations": lambda v: cfg.set_kdf_iterations(int(v)),
        "kdf_mode": lambda v: cfg.set_kdf_mode(v),
        "backup_interval": lambda v: cfg.set_backup_interval(float(v)),
        "nostr_max_retries": lambda v: cfg.set_nostr_max_retries(int(v)),
        "nostr_retry_delay": lambda v: cfg.set_nostr_retry_delay(float(v)),
        "min_uppercase": lambda v: cfg.set_min_uppercase(int(v)),
        "min_lowercase": lambda v: cfg.set_min_lowercase(int(v)),
        "min_digits": lambda v: cfg.set_min_digits(int(v)),
        "min_special": lambda v: cfg.set_min_special(int(v)),
        "quick_unlock": lambda v: cfg.set_quick_unlock(
            v.lower() in ("1", "true", "yes", "y", "on")
        ),
        "verbose_timing": lambda v: cfg.set_verbose_timing(
            v.lower() in ("1", "true", "yes", "y", "on")
        ),
    }

    action = mapping.get(key)
    if action is None:
        typer.echo("Unknown key")
        raise typer.Exit(code=1)

    try:
        action(value)
    except Exception as exc:  # pragma: no cover - pass through errors
        typer.echo(f"Error: {exc}")
        raise typer.Exit(code=1)

    typer.echo("Updated")


@config_app.command("toggle-secret-mode")
def config_toggle_secret_mode(ctx: typer.Context) -> None:
    """Interactively enable or disable secret mode."""
    pm = _get_pm(ctx)
    cfg = pm.config_manager
    try:
        enabled = cfg.get_secret_mode_enabled()
        delay = cfg.get_clipboard_clear_delay()
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
        cfg.set_secret_mode_enabled(enabled)
        cfg.set_clipboard_clear_delay(delay)
        pm.secret_mode_enabled = enabled
        pm.clipboard_clear_delay = delay
    except Exception as exc:  # pragma: no cover - pass through errors
        typer.echo(f"Error: {exc}")
        raise typer.Exit(code=1)

    status = "enabled" if enabled else "disabled"
    typer.echo(f"Secret mode {status}.")


@config_app.command("toggle-offline")
def config_toggle_offline(ctx: typer.Context) -> None:
    """Enable or disable offline mode."""
    pm = _get_pm(ctx)
    cfg = pm.config_manager
    try:
        enabled = cfg.get_offline_mode()
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
        cfg.set_offline_mode(enabled)
        pm.offline_mode = enabled
    except Exception as exc:  # pragma: no cover - pass through errors
        typer.echo(f"Error: {exc}")
        raise typer.Exit(code=1)

    status = "enabled" if enabled else "disabled"
    typer.echo(f"Offline mode {status}.")


@fingerprint_app.command("list")
def fingerprint_list(ctx: typer.Context) -> None:
    """List available seed profiles."""
    pm = _get_pm(ctx)
    for fp in pm.fingerprint_manager.list_fingerprints():
        typer.echo(fp)


@fingerprint_app.command("add")
def fingerprint_add(ctx: typer.Context) -> None:
    """Create a new seed profile."""
    pm = _get_pm(ctx)
    pm.add_new_fingerprint()


@fingerprint_app.command("remove")
def fingerprint_remove(ctx: typer.Context, fingerprint: str) -> None:
    """Remove a seed profile."""
    pm = _get_pm(ctx)
    pm.fingerprint_manager.remove_fingerprint(fingerprint)


@fingerprint_app.command("switch")
def fingerprint_switch(ctx: typer.Context, fingerprint: str) -> None:
    """Switch to another seed profile."""
    pm = _get_pm(ctx)
    pm.select_fingerprint(fingerprint)


@util_app.command("generate-password")
def generate_password(ctx: typer.Context, length: int = 24) -> None:
    """Generate a strong password."""
    pm = _get_pm(ctx)
    password = pm.password_generator.generate_password(length)
    typer.echo(password)


@util_app.command("verify-checksum")
def verify_checksum(ctx: typer.Context) -> None:
    """Verify the SeedPass script checksum."""
    pm = _get_pm(ctx)
    pm.handle_verify_checksum()


@util_app.command("update-checksum")
def update_checksum(ctx: typer.Context) -> None:
    """Regenerate the script checksum file."""
    pm = _get_pm(ctx)
    pm.handle_update_script_checksum()


@api_app.command("start")
def api_start(ctx: typer.Context, host: str = "127.0.0.1", port: int = 8000) -> None:
    """Start the SeedPass API server."""
    token = api_module.start_server(ctx.obj.get("fingerprint"))
    typer.echo(f"API token: {token}")
    uvicorn.run(api_module.app, host=host, port=port)


@api_app.command("stop")
def api_stop(ctx: typer.Context, host: str = "127.0.0.1", port: int = 8000) -> None:
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


if __name__ == "__main__":
    app()
