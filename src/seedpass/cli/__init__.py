from __future__ import annotations

import importlib
import importlib.util
import json
import subprocess
import sys
from typing import Optional

import typer

from .common import _get_services
from seedpass.core.errors import SeedPassError
from constants import GUI_BACKEND_CONFIG
from seedpass.tui_v2.app import check_tui2_runtime, launch_tui2

app = typer.Typer(
    help=(
        "SeedPass command line interface. "
        "Run `seedpass capabilities` for a deterministic feature map "
        "and `seedpass <group> --help` for group-specific commands, "
        "including document I/O and entry graph links."
    ),
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
)

deterministic_totp_option = typer.Option(
    False,
    "--deterministic-totp",
    help="Derive TOTP secrets deterministically",
)

# Sub command groups
from . import entry, vault, nostr, config, fingerprint, util, api, agent
from .capabilities import register_capabilities_command

app.add_typer(entry.app, name="entry")
app.add_typer(vault.app, name="vault")
app.add_typer(nostr.app, name="nostr")
app.add_typer(config.app, name="config")
app.add_typer(fingerprint.app, name="fingerprint")
app.add_typer(util.app, name="util")
app.add_typer(api.app, name="api")
app.add_typer(agent.app, name="agent")
register_capabilities_command(app)


def run() -> None:
    """Invoke the CLI, handling SeedPass errors gracefully."""
    try:
        app()
    except SeedPassError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc


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
    Use ``seedpass capabilities --format json`` for machine-readable command
    and security feature discovery.
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


@app.command("tui2")
def tui2(
    ctx: typer.Context,
    check: bool = typer.Option(
        False,
        "--check",
        help="Check whether TUI v2 runtime dependencies are available",
    ),
    fallback_legacy: bool = typer.Option(
        True,
        "--fallback-legacy/--no-fallback-legacy",
        help="Fall back to legacy TUI when TUI v2 runtime is unavailable",
    ),
) -> None:
    """Launch experimental TUI v2 scaffold."""
    if check:
        typer.echo(json.dumps(check_tui2_runtime(), indent=2, sort_keys=True))
        return

    fingerprint = (ctx.obj or {}).get("fingerprint")
    launched = launch_tui2(fingerprint=fingerprint)
    if launched:
        return

    if fallback_legacy:
        typer.echo(
            "TUI v2 runtime unavailable; falling back to legacy TUI. "
            "Run `seedpass tui2 --check` for diagnostics."
        )
        tui = importlib.import_module("main")
        raise typer.Exit(tui.main(fingerprint=fingerprint))

    typer.echo(
        "TUI v2 runtime unavailable. Install `textual` and retry.",
        err=True,
    )
    raise typer.Exit(1)


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
        platform_key = "linux" if sys.platform.startswith("linux") else sys.platform
        backend_info = GUI_BACKEND_CONFIG.get(platform_key)

        if not backend_info:
            typer.echo(
                f"Unsupported platform '{sys.platform}' for BeeWare GUI.",
                err=True,
            )
            raise typer.Exit(1)

        pkg = backend_info["pkg"]
        version = backend_info["version"]
        sha256 = backend_info["sha256"]

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
    run()
