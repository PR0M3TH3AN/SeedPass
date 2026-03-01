from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import click
import typer

from .common import (
    _get_services,
    ChangePasswordRequest,
    UnlockRequest,
    BackupParentSeedRequest,
)
from seedpass.core.agent_export_policy import (
    allowed_kinds,
    build_policy_filtered_export_package,
    evaluate_full_export,
    load_export_policy,
    record_export_policy_event,
)
from seedpass.core.agent_approval import approval_required, consume_approval
from seedpass.core.agent_secret_isolation import (
    high_risk_factor_configured,
    high_risk_unlocked,
)
from seedpass.core.auth_broker import (
    AuthBrokerError,
    resolve_password as resolve_broker_password,
)

app = typer.Typer(help="Manage the entire vault")


def _isolation_required_for_kind(policy: dict, kind: str) -> bool:
    cfg = policy.get("secret_isolation", {})
    if not isinstance(cfg, dict):
        return False
    if not bool(cfg.get("enabled", True)):
        return False
    kinds = cfg.get("high_risk_kinds", [])
    if not isinstance(kinds, list):
        return False
    return str(kind).lower() in {str(v).lower() for v in kinds}


@app.command("export")
def vault_export(
    ctx: typer.Context,
    file: str = typer.Option(..., help="Output file"),
    agent_profile: bool = typer.Option(
        False,
        "--agent-profile",
        help="Apply agent export policy controls",
    ),
    policy_filtered: bool = typer.Option(
        False,
        "--policy-filtered",
        help="Export only policy-allowed subset of entries",
    ),
    approval_id: Optional[str] = typer.Option(
        None,
        "--approval-id",
        help="Step-up approval id for actions requiring approval",
    ),
) -> None:
    """Export the vault profile to an encrypted file."""
    vault_service, _profile, _sync = _get_services(ctx)
    if agent_profile:
        policy = load_export_policy()
        if policy_filtered:
            manager = getattr(vault_service, "_manager", None)
            vault = getattr(manager, "vault", None)
            enc_mgr = getattr(vault, "encryption_manager", None)
            if vault is None or enc_mgr is None:
                typer.echo(
                    "Error: policy-filtered export unavailable in current context"
                )
                raise typer.Exit(code=1)
            index_data = vault.load_index()
            filtered = build_policy_filtered_export_package(index_data, policy)
            payload = json.dumps(
                filtered, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            data = enc_mgr.encrypt_data(payload)
            Path(file).write_bytes(data)
            record_export_policy_event(
                "export_allowed",
                {
                    "source": "cli:vault_export",
                    "mode": "filtered",
                    "file": str(file),
                    "allowed_kinds": sorted(list(allowed_kinds(policy))),
                    "policy_stamp": filtered.get("_export_manifest", {}).get(
                        "policy_stamp"
                    ),
                },
            )
            typer.echo(str(file))
            return
        allowed, reason = evaluate_full_export(policy)
        if not allowed:
            record_export_policy_event(
                "export_denied",
                {
                    "source": "cli:vault_export",
                    "mode": "full",
                    "reason": reason,
                    "file": str(file),
                },
            )
            typer.echo(f"Error: {reason}. Use --policy-filtered for subset export.")
            raise typer.Exit(code=1)
        if approval_required(policy, "export"):
            if not approval_id:
                reason = "policy_deny:approval_required"
                record_export_policy_event(
                    "export_denied",
                    {
                        "source": "cli:vault_export",
                        "mode": "full",
                        "reason": reason,
                        "file": str(file),
                    },
                )
                typer.echo(f"Error: {reason}. Provide --approval-id for full export.")
                raise typer.Exit(code=1)
            ok, approval_reason = consume_approval(
                approval_id=approval_id,
                action="export",
                resource="vault:full",
            )
            if not ok:
                reason = f"policy_deny:{approval_reason}"
                record_export_policy_event(
                    "export_denied",
                    {
                        "source": "cli:vault_export",
                        "mode": "full",
                        "reason": reason,
                        "file": str(file),
                    },
                )
                typer.echo(f"Error: {reason}")
                raise typer.Exit(code=1)
        record_export_policy_event(
            "export_allowed",
            {
                "source": "cli:vault_export",
                "mode": "full",
                "file": str(file),
                "approval_id": approval_id,
            },
        )
    else:
        policy = load_export_policy()

    if _isolation_required_for_kind(policy, "seed") and high_risk_factor_configured():
        fingerprint = str((ctx.obj or {}).get("fingerprint") or "default")
        unlocked, _expires_at = high_risk_unlocked(fingerprint=fingerprint)
        if not unlocked:
            typer.echo(
                "Error: policy_deny:high_risk_locked. Unlock high-risk session first."
            )
            raise typer.Exit(code=1)
    data = vault_service.export_profile()
    Path(file).write_bytes(data)
    typer.echo(str(file))


@app.command("import")
def vault_import(
    ctx: typer.Context, file: str = typer.Option(..., help="Input file")
) -> None:
    """Import a vault profile from an encrypted file."""
    vault_service, _profile, _sync = _get_services(ctx)
    data = Path(file).read_bytes()
    vault_service.import_profile(data)
    typer.echo(str(file))


@app.command("change-password")
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


@app.command("unlock")
def vault_unlock(
    ctx: typer.Context,
    auth_broker: str = typer.Option(
        "prompt",
        "--auth-broker",
        help="Password source for unlock (prompt|env|keyring|command)",
        click_type=click.Choice(
            ["prompt", "env", "keyring", "command"], case_sensitive=False
        ),
    ),
    password_env: str = typer.Option(
        "SEEDPASS_PASSWORD",
        "--password-env",
        help="Env var used when --auth-broker=env",
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
    """Unlock the vault for the active profile."""
    vault_service, _profile, _sync = _get_services(ctx)
    password: str
    if auth_broker.lower() == "prompt":
        password = typer.prompt("Master password", hide_input=True)
    else:
        account = broker_account or str((ctx.obj or {}).get("fingerprint") or "default")
        try:
            password = resolve_broker_password(
                broker=auth_broker,
                password_env=password_env,
                broker_service=broker_service,
                broker_account=account,
                broker_command=broker_command,
            )
        except AuthBrokerError as exc:
            raise typer.BadParameter(str(exc)) from exc
    try:
        resp = vault_service.unlock(UnlockRequest(password=password))
    except Exception as exc:  # pragma: no cover - pass through errors
        typer.echo(f"Error: {exc}")
        raise typer.Exit(code=1)
    typer.echo(f"Unlocked in {resp.duration:.2f}s")
    typer.echo(
        "Tip: run `seedpass --help`, `seedpass capabilities`, and `seedpass <command> --help` to discover features."
    )


@app.command("lock")
def vault_lock(ctx: typer.Context) -> None:
    """Lock the vault and clear sensitive data from memory."""
    vault_service, _profile, _sync = _get_services(ctx)
    vault_service.lock()
    typer.echo("locked")


@app.command("stats")
def vault_stats(ctx: typer.Context) -> None:
    """Display statistics about the current seed profile."""
    vault_service, _profile, _sync = _get_services(ctx)
    stats = vault_service.stats()
    typer.echo(json.dumps(stats, indent=2))


@app.command("reveal-parent-seed")
def vault_reveal_parent_seed(
    ctx: typer.Context,
    file: Optional[str] = typer.Option(
        None, "--file", help="Save encrypted seed to this path"
    ),
    agent_profile: bool = typer.Option(
        False,
        "--agent-profile",
        help="Apply agent approval policy controls",
    ),
    approval_id: Optional[str] = typer.Option(
        None,
        "--approval-id",
        help="Step-up approval id for reveal-parent-seed when required",
    ),
) -> None:
    """Display the parent seed and optionally write an encrypted backup file."""
    vault_service, _profile, _sync = _get_services(ctx)
    policy = load_export_policy()
    if _isolation_required_for_kind(policy, "seed") and high_risk_factor_configured():
        fingerprint = str((ctx.obj or {}).get("fingerprint") or "default")
        unlocked, _expires_at = high_risk_unlocked(fingerprint=fingerprint)
        if not unlocked:
            typer.echo(
                "Error: policy_deny:high_risk_locked. Unlock high-risk session first."
            )
            raise typer.Exit(code=1)
    if agent_profile:
        if approval_required(policy, "reveal_parent_seed"):
            if not approval_id:
                reason = "policy_deny:approval_required"
                record_export_policy_event(
                    "approval_denied",
                    {
                        "source": "cli:vault_reveal_parent_seed",
                        "reason": reason,
                        "action": "reveal_parent_seed",
                    },
                )
                typer.echo(f"Error: {reason}. Provide --approval-id.")
                raise typer.Exit(code=1)
            ok, approval_reason = consume_approval(
                approval_id=approval_id,
                action="reveal_parent_seed",
                resource="vault:parent-seed",
            )
            if not ok:
                reason = f"policy_deny:{approval_reason}"
                record_export_policy_event(
                    "approval_denied",
                    {
                        "source": "cli:vault_reveal_parent_seed",
                        "reason": reason,
                        "action": "reveal_parent_seed",
                        "approval_id": approval_id,
                    },
                )
                typer.echo(f"Error: {reason}")
                raise typer.Exit(code=1)
    password = typer.prompt("Master password", hide_input=True)
    vault_service.backup_parent_seed(
        BackupParentSeedRequest(path=Path(file) if file else None, password=password)
    )
    if agent_profile:
        record_export_policy_event(
            "approval_consumed",
            {
                "source": "cli:vault_reveal_parent_seed",
                "action": "reveal_parent_seed",
                "approval_id": approval_id,
                "file": str(file) if file else None,
            },
        )
