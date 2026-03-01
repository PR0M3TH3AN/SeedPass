from __future__ import annotations

import json
from typing import Any

import click
import typer


def build_capabilities() -> dict[str, Any]:
    """Return a deterministic capability map for CLI/API discovery."""
    return {
        "schema_version": 1,
        "product": "SeedPass",
        "interfaces": {
            "cli": {
                "root_commands": [
                    "lock",
                    "gui",
                    "capabilities",
                    "entry",
                    "vault",
                    "nostr",
                    "config",
                    "fingerprint",
                    "util",
                    "api",
                    "agent",
                ],
                "global_options": [
                    "--fingerprint",
                    "--no-clipboard",
                    "--deterministic-totp",
                ],
            },
            "api": {
                "discovery": ["/docs"],
                "auth_headers": ["Authorization: Bearer <token>"],
                "sensitive_auth_headers": ["X-SeedPass-Password"],
            },
        },
        "security_features": {
            "auth_brokers": {
                "available": ["env", "keyring", "command", "prompt"],
                "agent_commands": ["agent init", "agent get"],
                "vault_commands": ["vault unlock"],
                "api_commands": ["api start --unlock"],
            },
            "policy": {
                "commands": ["agent policy-show", "agent policy-lint", "agent policy-set"],
                "default_effect": "deny",
            },
            "tokens": {
                "commands": ["agent token-issue", "agent token-list", "agent token-revoke"],
                "supports_ttl": True,
                "supports_use_limits": True,
                "supports_revocation": True,
            },
            "redaction": {
                "default_safe_output": True,
                "reveal_override": "agent get --reveal",
            },
            "audit": {
                "log_file": "~/.seedpass/agent_audit.log",
                "integrity": "HMAC chained append-only records",
            },
        },
        "high_risk_operations": [
            "vault export",
            "vault reveal-parent-seed",
            "entry get (sensitive kinds)",
            "api /api/v1/vault/export",
        ],
        "help_hints": [
            "Run `seedpass --help` for top-level commands.",
            "Run `seedpass <group> --help` for detailed options.",
            "Use `seedpass capabilities --format json` for machine-readable discovery.",
        ],
    }


def emit_capabilities(output_format: str) -> str:
    data = build_capabilities()
    if output_format == "json":
        return json.dumps(data, indent=2, sort_keys=True)

    lines: list[str] = []
    lines.append("SeedPass Capabilities (schema v1)")
    lines.append("")
    lines.append("CLI root commands:")
    lines.append(", ".join(data["interfaces"]["cli"]["root_commands"]))
    lines.append("")
    lines.append("Security highlights:")
    lines.append("- Auth brokers: env, keyring, command, prompt")
    lines.append("- Policy controls: agent policy-show/policy-lint/policy-set")
    lines.append("- Scoped tokens: issue/list/revoke with TTL and use limits")
    lines.append("- Safe output redaction default with explicit --reveal")
    lines.append("- Audited access log with chained HMAC signatures")
    lines.append("")
    lines.append("Discovery hints:")
    for hint in data["help_hints"]:
        lines.append(f"- {hint}")
    return "\n".join(lines)


def register_capabilities_command(app: typer.Typer) -> None:
    @app.command("capabilities")
    def capabilities_command(
        format: str = typer.Option(
            "text",
            "--format",
            help="Output format for capabilities map",
            click_type=click.Choice(["text", "json"], case_sensitive=False),
        )
    ) -> None:
        """Show a deterministic capabilities map for users and agents."""
        typer.echo(emit_capabilities(format.lower()))
