from __future__ import annotations

import importlib
import importlib.util
import subprocess
import sys
from typing import Optional

import typer

from .common import _get_services

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

no_clipboard_option = typer.Option(
    False,
    "--no-clipboard",
    help="Disable clipboard support and print secrets instead",
    is_flag=True,
)

deterministic_totp_option = typer.Option(
    False,
    "--deterministic-totp",
    help="Derive TOTP secrets deterministically",
    is_flag=True,
)

# Sub command groups
from . import entry, vault, nostr, config, fingerprint, util, api

app.add_typer(entry.app, name="entry")
app.add_typer(vault.app, name="vault")
app.add_typer(nostr.app, name="nostr")
app.add_typer(config.app, name="config")
app.add_typer(fingerprint.app, name="fingerprint")
app.add_typer(util.app, name="util")
app.add_typer(api.app, name="api")


def _gui_backend_available() -> bool:
    """Return True if a platform-specific BeeWare backend is installed."""
    for pkg in ("toga_gtk", "toga_winforms", "toga_cocoa"):
        if importlib.util.find_spec(pkg) is not None:
            return True
    return False


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    fingerprint: Optional[str] = fingerprint_option,
    no_clipboard: bool = no_clipboard_option,
    deterministic_totp: bool = deterministic_totp_option,
) -> None:
    """SeedPass CLI entry point.

    When called without a subcommand this launches the interactive TUI.
    """
    ctx.obj = {
        "fingerprint": fingerprint,
        "no_clipboard": no_clipboard,
        "deterministic_totp": deterministic_totp,
    }
    if ctx.invoked_subcommand is None:
        tui = importlib.import_module("main")
        raise typer.Exit(tui.main(fingerprint=fingerprint))


@app.command("lock")
def root_lock(ctx: typer.Context) -> None:
    """Lock the vault for the active profile."""
    vault_service, _profile, _sync = _get_services(ctx)
    vault_service.lock()
    typer.echo("locked")


@app.command()
def gui(
    install: bool = typer.Option(
        False,
        "--install",
        help="Attempt to install the BeeWare GUI backend if missing",
    )
) -> None:
    """Launch the BeeWare GUI.

    If a platform specific backend is missing, inform the user how to
    install it. Using ``--install`` will attempt installation after
    confirmation.
    """
    if not _gui_backend_available():
        if sys.platform.startswith("linux"):
            pkg = "toga-gtk"
            version = "0.5.2"
            sha256 = "15b346ac1a2584de5effe5e73a3888f055c68c93300aeb111db9d64186b31646"
        elif sys.platform == "win32":
            pkg = "toga-winforms"
            version = "0.5.2"
            sha256 = "83181309f204bcc4a34709d23fdfd68467ae8ecc39c906d13c661cb9a0ef581b"
        elif sys.platform == "darwin":
            pkg = "toga-cocoa"
            version = "0.5.2"
            sha256 = "a4d5d1546bf92372a6fb1b450164735fb107b2ee69d15bf87421fec3c78465f9"
        else:
            typer.echo(
                f"Unsupported platform '{sys.platform}' for BeeWare GUI.",
                err=True,
            )
            raise typer.Exit(1)

        if not install:
            typer.echo(
                f"BeeWare GUI backend not found. Please install {pkg} manually or rerun "
                "with '--install'.",
                err=True,
            )
            raise typer.Exit(1)

        if not typer.confirm(
            f"Install {pkg}=={version} with hash verification?", default=False
        ):
            typer.echo("Installation cancelled.", err=True)
            raise typer.Exit(1)

        typer.echo(
            "SeedPass uses pinned versions and SHA256 hashes to verify the GUI backend "
            "and protect against tampered packages."
        )

        try:
            subprocess.check_call(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "install",
                    "--require-hashes",
                    f"{pkg}=={version}",
                    f"--hash=sha256:{sha256}",
                ]
            )
            typer.echo(f"Successfully installed {pkg}=={version}.")
        except subprocess.CalledProcessError as exc:
            typer.echo(
                "Secure installation failed. Please install the package manually "
                f"from a trusted source. Details: {exc}",
                err=True,
            )
            raise typer.Exit(1)

        if not _gui_backend_available():
            typer.echo(
                "BeeWare GUI backend still unavailable after installation attempt.",
                err=True,
            )
            raise typer.Exit(1)

    from seedpass_gui.app import main

    main()


if __name__ == "__main__":  # pragma: no cover
    app()
