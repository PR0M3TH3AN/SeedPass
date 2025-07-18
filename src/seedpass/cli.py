from pathlib import Path
from typing import Optional, List
import json

import typer

from seedpass.core.manager import PasswordManager
from seedpass.core.entry_types import EntryType
from seedpass.core.api import (
    VaultService,
    ProfileService,
    SyncService,
    EntryService,
    ConfigService,
    UtilityService,
    NostrService,
    VaultExportRequest,
    VaultImportRequest,
    ChangePasswordRequest,
    UnlockRequest,
    BackupParentSeedRequest,
    ProfileSwitchRequest,
    ProfileRemoveRequest,
)
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


def _get_services(
    ctx: typer.Context,
) -> tuple[VaultService, ProfileService, SyncService]:
    """Return service layer instances for the current context."""

    pm = _get_pm(ctx)
    return VaultService(pm), ProfileService(pm), SyncService(pm)


def _get_entry_service(ctx: typer.Context) -> EntryService:
    pm = _get_pm(ctx)
    return EntryService(pm)


def _get_config_service(ctx: typer.Context) -> ConfigService:
    pm = _get_pm(ctx)
    return ConfigService(pm)


def _get_util_service(ctx: typer.Context) -> UtilityService:
    pm = _get_pm(ctx)
    return UtilityService(pm)


def _get_nostr_service(ctx: typer.Context) -> NostrService:
    pm = _get_pm(ctx)
    return NostrService(pm)


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
        "index", "--sort", help="Sort by 'index', 'label', or 'updated'"
    ),
    kind: Optional[str] = typer.Option(None, "--kind", help="Filter by entry type"),
    archived: bool = typer.Option(False, "--archived", help="Include archived"),
) -> None:
    """List entries in the vault."""
    service = _get_entry_service(ctx)
    entries = service.list_entries(
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
def entry_search(
    ctx: typer.Context,
    query: str,
    kind: List[str] = typer.Option(
        None,
        "--kind",
        "-k",
        help="Filter by entry kinds (can be repeated)",
    ),
) -> None:
    """Search entries."""
    service = _get_entry_service(ctx)
    kinds = list(kind) if kind else None
    results = service.search_entries(query, kinds=kinds)
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
    service = _get_entry_service(ctx)
    matches = service.search_entries(query)
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


@entry_app.command("add")
def entry_add(
    ctx: typer.Context,
    label: str,
    length: int = typer.Option(12, "--length"),
    username: Optional[str] = typer.Option(None, "--username"),
    url: Optional[str] = typer.Option(None, "--url"),
) -> None:
    """Add a new password entry and output its index."""
    service = _get_entry_service(ctx)
    index = service.add_entry(label, length, username, url)
    typer.echo(str(index))


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
    service = _get_entry_service(ctx)
    uri = service.add_totp(
        label,
        index=index,
        secret=secret,
        period=period,
        digits=digits,
    )
    typer.echo(uri)


@entry_app.command("add-ssh")
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
    service = _get_entry_service(ctx)
    idx = service.add_pgp_key(
        label,
        index=index,
        key_type=key_type,
        user_id=user_id,
        notes=notes,
    )
    typer.echo(str(idx))


@entry_app.command("add-nostr")
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


@entry_app.command("add-seed")
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


@entry_app.command("add-key-value")
def entry_add_key_value(
    ctx: typer.Context,
    label: str,
    value: str = typer.Option(..., "--value", help="Stored value"),
    notes: str = typer.Option("", "--notes", help="Entry notes"),
) -> None:
    """Add a key/value entry and output its index."""
    service = _get_entry_service(ctx)
    idx = service.add_key_value(label, value, notes=notes)
    typer.echo(str(idx))


@entry_app.command("add-managed-account")
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
            value=value,
        )
    except ValueError as e:
        typer.echo(str(e))
        raise typer.Exit(code=1)


@entry_app.command("archive")
def entry_archive(ctx: typer.Context, entry_id: int) -> None:
    """Archive an entry."""
    service = _get_entry_service(ctx)
    service.archive_entry(entry_id)
    typer.echo(str(entry_id))


@entry_app.command("unarchive")
def entry_unarchive(ctx: typer.Context, entry_id: int) -> None:
    """Restore an archived entry."""
    service = _get_entry_service(ctx)
    service.restore_entry(entry_id)
    typer.echo(str(entry_id))


@entry_app.command("totp-codes")
def entry_totp_codes(ctx: typer.Context) -> None:
    """Display all current TOTP codes."""
    service = _get_entry_service(ctx)
    service.display_totp_codes()


@entry_app.command("export-totp")
def entry_export_totp(
    ctx: typer.Context, file: str = typer.Option(..., help="Output file")
) -> None:
    """Export all TOTP secrets to a JSON file."""
    service = _get_entry_service(ctx)
    data = service.export_totp_entries()
    Path(file).write_text(json.dumps(data, indent=2))
    typer.echo(str(file))


@vault_app.command("export")
def vault_export(
    ctx: typer.Context, file: str = typer.Option(..., help="Output file")
) -> None:
    """Export the vault."""
    vault_service, _profile, _sync = _get_services(ctx)
    vault_service.export_vault(VaultExportRequest(path=Path(file)))
    typer.echo(str(file))


@vault_app.command("import")
def vault_import(
    ctx: typer.Context, file: str = typer.Option(..., help="Input file")
) -> None:
    """Import a vault from an encrypted JSON file."""
    vault_service, _profile, _sync = _get_services(ctx)
    vault_service.import_vault(VaultImportRequest(path=Path(file)))
    typer.echo(str(file))


@vault_app.command("change-password")
def vault_change_password(ctx: typer.Context) -> None:
    """Change the master password used for encryption."""
    vault_service, _profile, _sync = _get_services(ctx)
    old_pw = typer.prompt("Current password", hide_input=True)
    new_pw = typer.prompt("New password", hide_input=True, confirmation_prompt=True)
    try:
        vault_service.change_password(
            ChangePasswordRequest(old_password=old_pw, new_password=new_pw)
        )
    except Exception as exc:  # pragma: no cover - pass through errors
        typer.echo(f"Error: {exc}")
        raise typer.Exit(code=1)
    typer.echo("Password updated")


@vault_app.command("unlock")
def vault_unlock(ctx: typer.Context) -> None:
    """Unlock the vault for the active profile."""
    vault_service, _profile, _sync = _get_services(ctx)
    password = typer.prompt("Master password", hide_input=True)
    try:
        resp = vault_service.unlock(UnlockRequest(password=password))
    except Exception as exc:  # pragma: no cover - pass through errors
        typer.echo(f"Error: {exc}")
        raise typer.Exit(code=1)
    typer.echo(f"Unlocked in {resp.duration:.2f}s")


@vault_app.command("lock")
def vault_lock(ctx: typer.Context) -> None:
    """Lock the vault and clear sensitive data from memory."""
    vault_service, _profile, _sync = _get_services(ctx)
    vault_service.lock()
    typer.echo("locked")


@vault_app.command("stats")
def vault_stats(ctx: typer.Context) -> None:
    """Display statistics about the current seed profile."""
    vault_service, _profile, _sync = _get_services(ctx)
    stats = vault_service.stats()
    typer.echo(json.dumps(stats, indent=2))


@vault_app.command("reveal-parent-seed")
def vault_reveal_parent_seed(
    ctx: typer.Context,
    file: Optional[str] = typer.Option(
        None, "--file", help="Save encrypted seed to this path"
    ),
) -> None:
    """Display the parent seed and optionally write an encrypted backup file."""
    vault_service, _profile, _sync = _get_services(ctx)
    password = typer.prompt("Master password", hide_input=True)
    vault_service.backup_parent_seed(
        BackupParentSeedRequest(path=Path(file) if file else None, password=password)
    )


@nostr_app.command("sync")
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


@nostr_app.command("get-pubkey")
def nostr_get_pubkey(ctx: typer.Context) -> None:
    """Display the active profile's npub."""
    service = _get_nostr_service(ctx)
    npub = service.get_pubkey()
    typer.echo(npub)


@nostr_app.command("list-relays")
def nostr_list_relays(ctx: typer.Context) -> None:
    """Display configured Nostr relays."""
    service = _get_nostr_service(ctx)
    relays = service.list_relays()
    for i, r in enumerate(relays, 1):
        typer.echo(f"{i}: {r}")


@nostr_app.command("add-relay")
def nostr_add_relay(ctx: typer.Context, url: str) -> None:
    """Add a relay URL."""
    service = _get_nostr_service(ctx)
    try:
        service.add_relay(url)
    except Exception as exc:  # pragma: no cover - pass through errors
        typer.echo(f"Error: {exc}")
        raise typer.Exit(code=1)
    typer.echo("Added")


@nostr_app.command("remove-relay")
def nostr_remove_relay(ctx: typer.Context, idx: int) -> None:
    """Remove a relay by index (1-based)."""
    service = _get_nostr_service(ctx)
    try:
        service.remove_relay(idx)
    except Exception as exc:  # pragma: no cover - pass through errors
        typer.echo(f"Error: {exc}")
        raise typer.Exit(code=1)
    typer.echo("Removed")


@config_app.command("get")
def config_get(ctx: typer.Context, key: str) -> None:
    """Get a configuration value."""
    service = _get_config_service(ctx)
    value = service.get(key)
    if value is None:
        typer.echo("Key not found")
    else:
        typer.echo(str(value))


@config_app.command("set")
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


@config_app.command("toggle-secret-mode")
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


@config_app.command("toggle-offline")
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


@fingerprint_app.command("list")
def fingerprint_list(ctx: typer.Context) -> None:
    """List available seed profiles."""
    _vault, profile_service, _sync = _get_services(ctx)
    for fp in profile_service.list_profiles():
        typer.echo(fp)


@fingerprint_app.command("add")
def fingerprint_add(ctx: typer.Context) -> None:
    """Create a new seed profile."""
    _vault, profile_service, _sync = _get_services(ctx)
    profile_service.add_profile()


@fingerprint_app.command("remove")
def fingerprint_remove(ctx: typer.Context, fingerprint: str) -> None:
    """Remove a seed profile."""
    _vault, profile_service, _sync = _get_services(ctx)
    profile_service.remove_profile(ProfileRemoveRequest(fingerprint=fingerprint))


@fingerprint_app.command("switch")
def fingerprint_switch(ctx: typer.Context, fingerprint: str) -> None:
    """Switch to another seed profile."""
    _vault, profile_service, _sync = _get_services(ctx)
    password = typer.prompt("Master password", hide_input=True)
    profile_service.switch_profile(
        ProfileSwitchRequest(fingerprint=fingerprint, password=password)
    )


@util_app.command("generate-password")
def generate_password(ctx: typer.Context, length: int = 24) -> None:
    """Generate a strong password."""
    service = _get_util_service(ctx)
    password = service.generate_password(length)
    typer.echo(password)


@util_app.command("verify-checksum")
def verify_checksum(ctx: typer.Context) -> None:
    """Verify the SeedPass script checksum."""
    service = _get_util_service(ctx)
    service.verify_checksum()


@util_app.command("update-checksum")
def update_checksum(ctx: typer.Context) -> None:
    """Regenerate the script checksum file."""
    service = _get_util_service(ctx)
    service.update_checksum()


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


@app.command()
def gui() -> None:
    """Launch the BeeWare GUI."""
    from seedpass_gui.app import main

    main()


if __name__ == "__main__":
    app()
