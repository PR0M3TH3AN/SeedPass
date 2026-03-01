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
                    "tui2",
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
                "discovery": [
                    "/docs",
                    "/api/v1/export/check",
                    "/api/v1/export/manifest/verify",
                    "/api/v1/entry/{id}/links",
                    "/api/v1/agent/job-profiles",
                    "/api/v1/agent/job-profiles/{job_id}/run",
                    "/api/v1/agent/job-profiles/{job_id}/template",
                    "/api/v1/agent/job-profiles/{job_id}/template/verify",
                    "/api/v1/agent/job-profiles/check",
                    "/api/v1/agent/recovery/split",
                    "/api/v1/agent/recovery/recover",
                    "/api/v1/agent/recovery/drill",
                    "/api/v1/agent/recovery/drills",
                    "/api/v1/agent/recovery/drills/verify",
                    "/api/v1/high-risk/status",
                    "/api/v1/high-risk/unlock",
                    "/api/v1/high-risk/lock",
                ],
                "auth_headers": ["Authorization: Bearer <token>"],
                "sensitive_auth_headers": [
                    "X-SeedPass-Password",
                    "X-SeedPass-Approval-Id",
                    "X-SeedPass-High-Risk-Factor",
                ],
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
                "commands": [
                    "agent policy-show",
                    "agent policy-lint",
                    "agent policy-set",
                    "agent policy-review",
                    "agent policy-apply",
                ],
                "default_effect": "deny",
                "supports_file_lint": True,
                "supports_change_review": True,
                "supports_risk_gated_apply": True,
            },
            "sync": {
                "deterministic_conflict_resolution": "modified_ts_hash_tombstone_v2",
                "supports_tombstones": True,
                "metadata_fields": ["_sync_meta.strategy", "_sync_meta.tombstones"],
            },
            "tokens": {
                "commands": [
                    "agent token-issue",
                    "agent token-list",
                    "agent token-revoke",
                ],
                "supports_ttl": True,
                "supports_use_limits": True,
                "supports_revocation": True,
            },
            "identities": {
                "commands": [
                    "agent identity-create",
                    "agent identity-list",
                    "agent identity-revoke",
                ],
                "token_binding_required_for_new_tokens": True,
                "supports_revocation": True,
            },
            "leases": {
                "commands": [
                    "agent get --lease-only",
                    "agent lease-consume",
                    "agent lease-list",
                    "agent lease-revoke",
                ],
                "supports_ttl": True,
                "supports_use_limits": True,
                "supports_one_time": True,
            },
            "automation": {
                "commands": [
                    "agent job-run",
                    "agent job-template",
                    "agent job-profile-create",
                    "agent job-profile-list",
                    "agent job-profile-run",
                    "agent job-profile-revoke",
                    "agent job-profile-check",
                ],
                "safe_default_brokers": ["keyring", "command"],
                "supports_cron_templates": True,
                "supports_systemd_templates": True,
                "supports_api_templates": True,
                "supports_persistent_job_profiles": True,
                "enforces_policy_stamp_on_run": True,
                "supports_host_binding": True,
                "template_manifest_signing": "hmac-sha256",
            },
            "recovery": {
                "commands": [
                    "agent recovery-split",
                    "agent recovery-recover",
                    "agent recovery-drill",
                    "agent recovery-drill-list",
                ],
                "supports_shamir_split_recover": True,
                "supports_signed_drill_reports": True,
            },
            "secret_isolation": {
                "commands": [
                    "agent high-risk-factor-set",
                    "agent high-risk-unlock",
                    "agent high-risk-status",
                    "agent high-risk-lock",
                ],
                "high_risk_classes": ["seed", "ssh", "pgp", "nostr", "managed_account"],
                "separate_unlock_factor": True,
            },
            "approvals": {
                "commands": [
                    "agent approval-issue",
                    "agent approval-list",
                    "agent approval-revoke",
                ],
                "supports_ttl": True,
                "supports_use_limits": True,
                "enforced_on": [
                    "vault export (full, agent mode)",
                    "api /api/v1/vault/export",
                    "vault reveal-parent-seed (agent mode)",
                    "agent get --reveal (private kinds)",
                ],
            },
            "export_controls": {
                "commands": [
                    "vault export --agent-profile --policy-filtered",
                    "agent export-check",
                    "agent export-manifest-verify",
                ],
                "default_full_export_agent_profile": "denied",
                "supports_policy_filtered_export": True,
                "supports_manifest_entry_hash_verification": True,
                "manifest_mode": "policy_filtered",
            },
            "document_io": {
                "commands": [
                    "entry import-document",
                    "entry export-document",
                    "agent document-import",
                    "agent document-export",
                ],
                "requires_agent_export_import_policy": True,
            },
            "knowledge_graph": {
                "commands": [
                    "entry link-add",
                    "entry links",
                    "entry link-remove",
                    "entry modify --links-json",
                ],
                "api_endpoints": [
                    "GET /api/v1/entry/{id}/links",
                    "POST /api/v1/entry/{id}/links",
                    "DELETE /api/v1/entry/{id}/links",
                ],
                "search_includes_link_metadata": True,
                "sync_union_merge_fields": ["tags", "custom_fields", "links"],
            },
            "redaction": {
                "default_safe_output": True,
                "reveal_override": "agent get --reveal",
            },
            "posture": {
                "commands": ["agent posture-check", "agent posture-remediate"],
                "checks": [
                    "policy validity",
                    "token ttl/usage hygiene",
                    "token rotation overdue against identity policy",
                    "identity-token binding integrity",
                    "approval gate completeness for risky actions",
                    "over-permissive secret-read rule detection",
                    "high-risk factor readiness",
                    "high-risk unlock TTL sanity",
                    "runtime config drift (quick unlock, weak KDF, partition unlock state)",
                ],
            },
            "audit": {
                "log_file": "~/.seedpass/agent_audit.log",
                "integrity": "HMAC chained append-only records",
            },
        },
        "high_risk_operations": [
            "vault export",
            "vault reveal-parent-seed",
            "agent get --reveal (sensitive kinds)",
            "api /api/v1/vault/export",
            "api /api/v1/vault/backup-parent-seed",
        ],
        "help_hints": [
            "Run `seedpass --help` for top-level commands.",
            "Run `seedpass <group> --help` for detailed options.",
            "Use `seedpass capabilities --format json` for machine-readable discovery.",
            "Run `seedpass tui2 --check` before adopting Textual-based TUI v2.",
            "Use `seedpass --legacy-tui` to force the legacy interface during cutover.",
            "In TUI v2, use `?` for help, `j` to jump to entry id, `1/2/3` to focus panes, `Ctrl+P` for palette, `p/n` for paging, and `x` to retry.",
            "For graph workflows, start with `seedpass entry link-add --help` and `seedpass entry links --help`.",
            "For document workflows, run `seedpass entry import-document --help` and `seedpass agent document-import --help`.",
            "After unlock/login, run `seedpass capabilities` before autonomous runs.",
            "For agent bootstrap context, run `seedpass agent bootstrap-context`.",
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
    lines.append(
        "- Policy as code: policy-show/lint/review/apply with deterministic hashes"
    )
    lines.append("- Sync safety: deterministic conflicts with tombstones")
    lines.append("- Scoped tokens: issue/list/revoke with TTL and use limits")
    lines.append("- Agent identities: create/list/revoke and bind tokens")
    lines.append("- Secret leases: lease-only issue and bounded lease-consume")
    lines.append(
        "- Automation primitives: job-run with safe brokers and cron/systemd templates"
    )
    lines.append(
        "- Recovery hardening: Shamir split/recover and signed backup drill logs"
    )
    lines.append("- Secret class isolation: separate high-risk unlock factor/session")
    lines.append("- Approval gates: issue/list/revoke for risky actions")
    lines.append("- Deterministic export controls with manifest verification")
    lines.append("- Safe output redaction default with explicit --reveal")
    lines.append("- Security posture checks and remediation bundles")
    lines.append("- Audited access log with chained HMAC signatures")
    lines.append("- Knowledge graph links: entry link-add/links/link-remove")
    lines.append("- Document file workflows for users and agents")
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
