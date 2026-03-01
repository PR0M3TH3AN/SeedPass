from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import bcrypt
import click
import typer
from bip_utils import Bip39Languages, Bip39MnemonicGenerator, Bip39WordsNum
from mnemonic import Mnemonic

from constants import APP_DIR, initialize_app
from seedpass.core.api import EntryService
from seedpass.core.auth_broker import (
    AuthBrokerError,
    resolve_password as resolve_broker_password,
)
from seedpass.core.entry_types import ALL_ENTRY_TYPES, EntryType
from seedpass.core.encryption import EncryptionManager
from seedpass.core.manager import PasswordManager
from seedpass.core.vault import Vault
from seedpass.core.config_manager import ConfigManager
from utils.fingerprint import generate_fingerprint
from utils.fingerprint_manager import FingerprintManager
from utils.key_derivation import derive_index_key, derive_key_from_password

app = typer.Typer(help="Agent-first non-interactive workflows")

PRIVATE_KINDS = {
    EntryType.SEED.value,
    EntryType.SSH.value,
    EntryType.PGP.value,
    EntryType.NOSTR.value,
    EntryType.MANAGED_ACCOUNT.value,
}

DEFAULT_POLICY = {
    "version": 1,
    "default_effect": "deny",
    "rules": [
        {
            "id": "allow_standard_read",
            "effect": "allow",
            "operations": ["read"],
            "kinds": [
                EntryType.PASSWORD.value,
                EntryType.TOTP.value,
                EntryType.KEY_VALUE.value,
            ],
            "label_regex": ".*",
            "path_regex": "^entry/.*$",
            "fields": ["secret", "label", "kind"],
        },
        {
            "id": "deny_private_material",
            "effect": "deny",
            "operations": ["read"],
            "kinds": sorted(PRIVATE_KINDS),
            "label_regex": ".*",
            "path_regex": "^entry/.*$",
            "fields": ["secret"],
        },
    ],
    "approvals": {
        "require_for": [
            "export",
            "reveal_parent_seed",
            "private_key_retrieval",
        ]
    },
    "output": {
        "safe_output_default": True,
        "redact_fields": ["secret", "value", "private_key", "seed_phrase"],
    },
    "export": {
        "allow_full_vault": False,
    },
    # Legacy compatibility fields kept for older consumers/tests.
    "allow_kinds": [
        EntryType.PASSWORD.value,
        EntryType.TOTP.value,
        EntryType.KEY_VALUE.value,
    ],
    "deny_private_reveal": sorted(PRIVATE_KINDS),
    "allow_export_import": False,
}

TOKEN_STORE_VERSION = 1


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _policy_path() -> Path:
    return APP_DIR / "agent_policy.json"


def _token_store_path() -> Path:
    return APP_DIR / "agent_tokens.json"


def _audit_key_path() -> Path:
    return APP_DIR / "agent_audit.key"


def _audit_log_path() -> Path:
    return APP_DIR / "agent_audit.log"


def _ensure_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _mask_secret(value: str | None) -> str | None:
    if value is None:
        return None
    if len(value) <= 4:
        return "*" * len(value)
    return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"


def _deny_all_policy() -> dict[str, Any]:
    deny = {
        "version": 1,
        "default_effect": "deny",
        "rules": [],
        "approvals": {"require_for": ["export", "reveal_parent_seed"]},
        "output": {
            "safe_output_default": True,
            "redact_fields": ["secret", "value", "private_key", "seed_phrase"],
        },
        "export": {"allow_full_vault": False},
        "allow_kinds": [],
        "deny_private_reveal": list(ALL_ENTRY_TYPES),
        "allow_export_import": False,
    }
    return deny


def _normalize_legacy_policy(data: dict[str, Any]) -> dict[str, Any]:
    """Convert legacy policy keys into the versioned rule model."""
    allow_kinds_raw = data.get("allow_kinds")
    deny_private_raw = data.get("deny_private_reveal")
    allow_export_import = bool(data.get("allow_export_import", False))

    allow_kinds = (
        [str(v) for v in allow_kinds_raw if str(v) in ALL_ENTRY_TYPES]
        if isinstance(allow_kinds_raw, list)
        else list(DEFAULT_POLICY["allow_kinds"])
    )
    deny_private = (
        [str(v) for v in deny_private_raw if str(v) in ALL_ENTRY_TYPES]
        if isinstance(deny_private_raw, list)
        else list(DEFAULT_POLICY["deny_private_reveal"])
    )

    policy = dict(DEFAULT_POLICY)
    rules: list[dict[str, Any]] = [
        {
            "id": "allow_standard_read",
            "effect": "allow",
            "operations": ["read"],
            "kinds": allow_kinds,
            "label_regex": ".*",
            "path_regex": "^entry/.*$",
            "fields": ["secret", "label", "kind"],
        }
    ]
    if deny_private:
        rules.append(
            {
                "id": "deny_private_material",
                "effect": "deny",
                "operations": ["read"],
                "kinds": deny_private,
                "label_regex": ".*",
                "path_regex": "^entry/.*$",
                "fields": ["secret"],
            }
        )
    policy["rules"] = rules
    policy["allow_kinds"] = allow_kinds
    policy["deny_private_reveal"] = deny_private
    policy["allow_export_import"] = allow_export_import
    policy["export"] = {"allow_full_vault": allow_export_import}
    policy["output"] = dict(DEFAULT_POLICY["output"])
    return policy


def _validate_rule(rule: dict[str, Any]) -> None:
    effect = str(rule.get("effect", "")).lower()
    if effect not in {"allow", "deny"}:
        raise ValueError("rule effect must be 'allow' or 'deny'")

    operations = rule.get("operations", [])
    if not isinstance(operations, list) or not operations:
        raise ValueError("rule operations must be a non-empty list")
    for op in operations:
        if not isinstance(op, str):
            raise ValueError("rule operations entries must be strings")

    kinds = rule.get("kinds", [])
    if not isinstance(kinds, list):
        raise ValueError("rule kinds must be a list")
    invalid_kinds = [k for k in kinds if str(k) not in ALL_ENTRY_TYPES]
    if invalid_kinds:
        raise ValueError(f"rule contains invalid kinds: {invalid_kinds}")

    for regex_key in ("label_regex", "path_regex"):
        pattern = rule.get(regex_key, ".*")
        if not isinstance(pattern, str):
            raise ValueError(f"rule {regex_key} must be a string")
        try:
            re.compile(pattern)
        except re.error as exc:  # pragma: no cover - exercised via CLI path
            raise ValueError(f"invalid {regex_key}: {exc}") from exc

    fields = rule.get("fields", [])
    if not isinstance(fields, list) or any(not isinstance(f, str) for f in fields):
        raise ValueError("rule fields must be a list of strings")


def _normalize_policy(data: dict[str, Any], *, strict: bool) -> dict[str, Any]:
    if "rules" not in data:
        return _normalize_legacy_policy(data)

    policy = dict(DEFAULT_POLICY)
    policy.update({k: v for k, v in data.items() if k in policy})

    version = int(policy.get("version", 1))
    if version != 1:
        raise ValueError("agent policy version must be 1")

    default_effect = str(policy.get("default_effect", "deny")).lower()
    if default_effect not in {"allow", "deny"}:
        raise ValueError("default_effect must be 'allow' or 'deny'")
    policy["default_effect"] = default_effect

    raw_rules = policy.get("rules", [])
    if not isinstance(raw_rules, list):
        raise ValueError("policy rules must be a list")

    normalized_rules: list[dict[str, Any]] = []
    for rule in raw_rules:
        if not isinstance(rule, dict):
            raise ValueError("each policy rule must be an object")
        _validate_rule(rule)
        normalized_rules.append(
            {
                "id": str(rule.get("id", "rule")),
                "effect": str(rule.get("effect", "")).lower(),
                "operations": [str(v) for v in rule.get("operations", [])],
                "kinds": [str(v) for v in rule.get("kinds", [])],
                "label_regex": str(rule.get("label_regex", ".*")),
                "path_regex": str(rule.get("path_regex", ".*")),
                "fields": [str(v) for v in rule.get("fields", [])],
            }
        )
    policy["rules"] = normalized_rules

    output_cfg = policy.get("output")
    if not isinstance(output_cfg, dict):
        output_cfg = {}
    output_norm = dict(DEFAULT_POLICY["output"])
    if "safe_output_default" in output_cfg:
        output_norm["safe_output_default"] = bool(output_cfg["safe_output_default"])
    redact_fields = output_cfg.get("redact_fields")
    if isinstance(redact_fields, list):
        output_norm["redact_fields"] = [str(v) for v in redact_fields]
    policy["output"] = output_norm

    export_cfg = policy.get("export")
    if not isinstance(export_cfg, dict):
        export_cfg = {}
    policy["export"] = {
        "allow_full_vault": bool(export_cfg.get("allow_full_vault", False))
    }

    # Keep compatibility fields in sync with rule model.
    allow_kinds = sorted(
        {
            k
            for r in normalized_rules
            if r["effect"] == "allow" and "read" in r["operations"]
            for k in r["kinds"]
        }
    )
    deny_private = sorted(
        {
            k
            for r in normalized_rules
            if r["effect"] == "deny" and "read" in r["operations"]
            for k in r["kinds"]
            if k in PRIVATE_KINDS
        }
    )
    policy["allow_kinds"] = allow_kinds
    policy["deny_private_reveal"] = deny_private
    policy["allow_export_import"] = bool(policy["export"]["allow_full_vault"])

    if strict:
        # Force full validation for future schema updates.
        for rule in policy["rules"]:
            _validate_rule(rule)

    return policy


def _load_policy(*, strict: bool = False) -> dict[str, Any]:
    path = _policy_path()
    if not path.exists():
        return dict(DEFAULT_POLICY)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        if strict:
            raise ValueError("agent policy file is not valid JSON") from exc
        return _deny_all_policy()

    if not isinstance(data, dict):
        if strict:
            raise ValueError("agent policy file must be a JSON object")
        return _deny_all_policy()

    try:
        return _normalize_policy(data, strict=strict)
    except ValueError:
        if strict:
            raise
        return _deny_all_policy()


def _save_policy(policy: dict[str, Any]) -> None:
    path = _policy_path()
    _ensure_dir(path)
    normalized = _normalize_policy(policy, strict=True)
    path.write_text(json.dumps(normalized, indent=2), encoding="utf-8")
    os.chmod(path, 0o600)


def _agent_password(
    *,
    broker: str,
    password_env: str,
    broker_service: str,
    broker_account: str,
    broker_command: str | None,
) -> str:
    try:
        return resolve_broker_password(
            broker=broker,
            password_env=password_env,
            broker_service=broker_service,
            broker_account=broker_account,
            broker_command=broker_command,
        )
    except AuthBrokerError as exc:
        raise typer.BadParameter(str(exc)) from exc


def _seed_from_inputs(
    seed: Optional[str],
    seed_file: Optional[Path],
    generate_seed: bool,
) -> tuple[str, bool]:
    choices = int(bool(seed)) + int(bool(seed_file)) + int(bool(generate_seed))
    if choices != 1:
        raise typer.BadParameter(
            "Provide exactly one of --seed, --seed-file, or --generate-seed."
        )
    if seed_file:
        seed = seed_file.read_text(encoding="utf-8").strip()
    elif generate_seed:
        seed = (
            Bip39MnemonicGenerator(Bip39Languages.ENGLISH)
            .FromWordsNumber(Bip39WordsNum.WORDS_NUM_12)
            .ToStr()
        )
    assert seed is not None
    if not Mnemonic("english").check(seed):
        raise typer.BadParameter("Invalid BIP-39 seed phrase.")
    return seed, bool(generate_seed)


def _load_token_store() -> dict[str, Any]:
    path = _token_store_path()
    if not path.exists():
        return {"version": TOKEN_STORE_VERSION, "tokens": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"version": TOKEN_STORE_VERSION, "tokens": []}
    if not isinstance(data, dict) or not isinstance(data.get("tokens"), list):
        return {"version": TOKEN_STORE_VERSION, "tokens": []}
    return data


def _save_token_store(store: dict[str, Any]) -> None:
    path = _token_store_path()
    _ensure_dir(path)
    path.write_text(json.dumps(store, indent=2), encoding="utf-8")
    os.chmod(path, 0o600)


def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _issue_token_record(
    name: str,
    ttl: int,
    scopes: list[str],
    kinds: list[str],
    label_regex: str,
    uses: int,
) -> tuple[str, dict[str, Any]]:
    raw = secrets.token_urlsafe(32)
    now = _utcnow()
    token_id = hashlib.blake2s(raw.encode("utf-8"), digest_size=8).hexdigest()
    record = {
        "id": token_id,
        "name": name,
        "token_hash": _hash_token(raw),
        "created_at_utc": now.isoformat(),
        "expires_at_utc": (now + timedelta(seconds=ttl)).isoformat(),
        "revoked_at_utc": None,
        "scopes": scopes,
        "kinds": kinds,
        "label_regex": label_regex,
        "uses_remaining": int(uses),
    }
    return raw, record


def _parse_iso8601(value: str) -> datetime:
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _validate_token(
    raw_token: str,
    *,
    operation: str,
    kind: str,
    label: str,
    consume_use: bool,
) -> tuple[bool, str, dict[str, Any] | None]:
    store = _load_token_store()
    digest = _hash_token(raw_token)
    for rec in store.get("tokens", []):
        if rec.get("token_hash") != digest:
            continue
        if rec.get("revoked_at_utc"):
            return False, "token_revoked", None
        exp = rec.get("expires_at_utc")
        if not exp or _utcnow() >= _parse_iso8601(exp):
            return False, "token_expired", None

        scopes = [str(s) for s in rec.get("scopes", [])]
        if operation not in scopes:
            return False, "token_scope_denied", None

        kinds = [str(k) for k in rec.get("kinds", [])]
        if kinds and kind not in kinds:
            return False, "token_kind_denied", None

        label_regex = str(rec.get("label_regex", ".*"))
        try:
            if not re.search(label_regex, label):
                return False, "token_label_denied", None
        except re.error:
            return False, "token_invalid_regex", None

        uses_remaining = int(rec.get("uses_remaining", 0))
        if uses_remaining <= 0:
            return False, "token_exhausted", None

        if consume_use:
            rec["uses_remaining"] = uses_remaining - 1
            _save_token_store(store)

        return True, "ok", rec

    return False, "token_not_found", None


def _load_audit_key() -> bytes:
    path = _audit_key_path()
    if path.exists():
        return path.read_bytes()
    _ensure_dir(path)
    key = secrets.token_bytes(32)
    path.write_bytes(key)
    os.chmod(path, 0o600)
    return key


def _append_audit_event(event: str, details: dict[str, Any]) -> None:
    key = _load_audit_key()
    path = _audit_log_path()
    _ensure_dir(path)

    prev_sig = "0" * 64
    if path.exists():
        try:
            lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln]
            if lines:
                prev = json.loads(lines[-1])
                prev_sig = str(prev.get("sig", prev_sig))
        except Exception:
            prev_sig = "0" * 64

    payload = {
        "timestamp_utc": _utcnow().isoformat(),
        "host": socket.gethostname(),
        "event": event,
        "details": details,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    sig = hmac.new(key, f"{prev_sig}{canonical}".encode("utf-8"), hashlib.sha256)
    payload["sig"] = sig.hexdigest()

    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, sort_keys=True) + "\n")
    os.chmod(path, 0o600)


def _policy_decision(
    policy: dict[str, Any],
    *,
    operation: str,
    kind: str,
    label: str,
    path: str,
    field: str,
) -> tuple[bool, str]:
    matched_allow = None
    for rule in policy.get("rules", []):
        operations = set(rule.get("operations", []))
        kinds = set(rule.get("kinds", []))
        fields = set(rule.get("fields", []))
        if operation not in operations:
            continue
        if kinds and kind not in kinds:
            continue
        if fields and field not in fields:
            continue
        try:
            if not re.search(str(rule.get("label_regex", ".*")), label):
                continue
            if not re.search(str(rule.get("path_regex", ".*")), path):
                continue
        except re.error:
            continue

        effect = str(rule.get("effect", "")).lower()
        rid = str(rule.get("id", "rule"))
        if effect == "deny":
            return False, f"policy_deny:{rid}"
        if effect == "allow":
            matched_allow = rid

    if matched_allow:
        return True, f"policy_allow:{matched_allow}"

    if policy.get("default_effect", "deny") == "allow":
        return True, "policy_default_allow"
    return False, "policy_default_deny"


def _build_entry_path(index: int, kind: str, label: str) -> str:
    return f"entry/{index}/{kind}/{label}"


def _token_posture_summary() -> dict[str, int]:
    store = _load_token_store()
    now = _utcnow()
    total = 0
    active = 0
    revoked = 0
    expired = 0
    exhausted = 0
    for rec in store.get("tokens", []):
        total += 1
        if rec.get("revoked_at_utc"):
            revoked += 1
            continue
        exp = rec.get("expires_at_utc")
        if exp:
            try:
                if _parse_iso8601(exp) <= now:
                    expired += 1
                    continue
            except Exception:
                expired += 1
                continue
        if int(rec.get("uses_remaining", 0)) <= 0:
            exhausted += 1
            continue
        active += 1
    return {
        "total": total,
        "active": active,
        "revoked": revoked,
        "expired": expired,
        "exhausted": exhausted,
    }


def _severity_rank(severity: str) -> int:
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return order.get(severity, 0)


def _posture_findings(
    policy: dict[str, Any], policy_status: str
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if policy_status != "ok":
        findings.append(
            {
                "id": "policy_invalid",
                "severity": "critical",
                "message": "Agent policy JSON is invalid; default deny fallback may block operations.",
                "remediation": "Run `seedpass agent policy-lint` and fix policy syntax/schema.",
            }
        )

    if str(policy.get("default_effect", "deny")).lower() == "allow":
        findings.append(
            {
                "id": "policy_default_allow",
                "severity": "high",
                "message": "Policy default effect is allow; unmatched operations are permitted.",
                "remediation": "Set `default_effect` to `deny` and add explicit allow rules.",
            }
        )

    if len(policy.get("rules", [])) == 0:
        findings.append(
            {
                "id": "policy_no_rules",
                "severity": "medium",
                "message": "Policy has no rules; behavior depends entirely on default effect.",
                "remediation": "Define explicit allow/deny rules for read/create/update/export.",
            }
        )

    if bool(policy.get("allow_export_import", False)):
        findings.append(
            {
                "id": "export_import_allowed",
                "severity": "high",
                "message": "Agent export/import is enabled.",
                "remediation": "Disable export/import for agent profiles unless explicitly required.",
            }
        )

    if not bool(policy.get("output", {}).get("safe_output_default", True)):
        findings.append(
            {
                "id": "safe_output_disabled",
                "severity": "high",
                "message": "Safe output default is disabled; secrets may leak into logs/stdout.",
                "remediation": "Set output.safe_output_default to true.",
            }
        )

    store = _load_token_store()
    now = _utcnow()
    long_lived = 0
    broad_scope = 0
    for rec in store.get("tokens", []):
        if rec.get("revoked_at_utc"):
            continue
        exp = rec.get("expires_at_utc")
        created = rec.get("created_at_utc")
        try:
            if exp and created:
                ttl = (_parse_iso8601(exp) - _parse_iso8601(created)).total_seconds()
                if ttl > 86400:
                    long_lived += 1
        except Exception:
            pass

        scopes = [str(v) for v in rec.get("scopes", [])]
        if "export" in scopes or "reveal_parent_seed" in scopes:
            broad_scope += 1
        elif not scopes:
            broad_scope += 1

        if exp:
            try:
                if _parse_iso8601(exp) <= now:
                    findings.append(
                        {
                            "id": "expired_tokens_present",
                            "severity": "low",
                            "message": "Expired tokens are present in token store.",
                            "remediation": "Periodically prune expired token records.",
                        }
                    )
                    break
            except Exception:
                pass

    if long_lived:
        findings.append(
            {
                "id": "long_lived_tokens",
                "severity": "medium",
                "message": f"{long_lived} active token(s) exceed 24h TTL.",
                "remediation": "Reduce token TTLs and rotate often.",
            }
        )
    if broad_scope:
        findings.append(
            {
                "id": "overbroad_token_scopes",
                "severity": "high",
                "message": f"{broad_scope} token(s) include broad or risky scopes.",
                "remediation": "Issue least-privilege tokens (prefer read-only, narrow kinds/labels).",
            }
        )

    return findings


@app.command("init")
def agent_init(
    seed: Optional[str] = typer.Option(
        None, "--seed", help="BIP-39 seed phrase (avoid shell history for secrets)"
    ),
    seed_file: Optional[Path] = typer.Option(
        None, "--seed-file", help="Path to a file containing the seed phrase"
    ),
    generate_seed: bool = typer.Option(
        False, "--generate-seed", help="Generate a fresh 12-word seed"
    ),
    password_env: str = typer.Option(
        "SEEDPASS_PASSWORD", "--password-env", help="Env var containing master password"
    ),
    auth_broker: str = typer.Option(
        "env",
        "--auth-broker",
        help="Non-interactive password broker (env|keyring|command)",
        click_type=click.Choice(["env", "keyring", "command"], case_sensitive=False),
    ),
    broker_service: str = typer.Option(
        "seedpass",
        "--broker-service",
        help="Keyring service name when --auth-broker=keyring",
    ),
    broker_account: str = typer.Option(
        "default",
        "--broker-account",
        help="Keyring account (or logical broker identity)",
    ),
    broker_command: Optional[str] = typer.Option(
        None,
        "--broker-command",
        help="Command that prints password to stdout for --auth-broker=command",
    ),
    switch_existing: bool = typer.Option(
        False,
        "--switch-existing",
        help="Switch to existing profile if the seed fingerprint already exists",
    ),
    kdf_iterations: int = typer.Option(
        200_000, "--kdf-iterations", help="PBKDF2 iterations for profile setup"
    ),
    print_seed: bool = typer.Option(
        False, "--print-seed", help="Include generated seed in JSON output"
    ),
) -> None:
    """Initialize a profile non-interactively for agent workflows."""
    initialize_app()
    password = _agent_password(
        broker=auth_broker,
        password_env=password_env,
        broker_service=broker_service,
        broker_account=broker_account,
        broker_command=broker_command,
    )
    seed_phrase, generated = _seed_from_inputs(seed, seed_file, generate_seed)

    fp_mgr = FingerprintManager(APP_DIR)
    fingerprint = None
    created = False
    try:
        fingerprint = fp_mgr.add_fingerprint(seed_phrase)
        created = True
    except ValueError:
        fingerprint = generate_fingerprint(seed_phrase)
        if not switch_existing:
            raise typer.BadParameter(
                "Seed profile already exists. Use --switch-existing to reuse it."
            )

    assert fingerprint is not None
    profile_dir = fp_mgr.get_fingerprint_directory(fingerprint)
    if profile_dir is None:
        raise typer.BadParameter("Could not resolve profile directory for fingerprint.")
    profile_dir.mkdir(parents=True, exist_ok=True)

    seed_key = derive_key_from_password(
        password, fingerprint, iterations=kdf_iterations
    )
    seed_mgr = EncryptionManager(seed_key, profile_dir)
    seed_mgr.encrypt_parent_seed(seed_phrase)

    index_key = derive_index_key(seed_phrase)
    enc_mgr = EncryptionManager(index_key, profile_dir)
    vault = Vault(enc_mgr, profile_dir)
    cfg = ConfigManager(vault=vault, fingerprint_dir=profile_dir)
    cfg.set_password_hash(bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode())
    cfg.set_kdf_iterations(kdf_iterations)
    cfg.set_offline_mode(True)
    cfg.set_secret_mode_enabled(False)
    cfg.set_quick_unlock(False)

    if not _policy_path().exists():
        _save_policy(dict(DEFAULT_POLICY))

    payload = {
        "status": "ok",
        "created": created,
        "fingerprint": fingerprint,
        "profile_dir": str(profile_dir),
        "generated_seed": seed_phrase if generated and print_seed else None,
    }
    typer.echo(json.dumps(payload, indent=2))


@app.command("policy-show")
def agent_policy_show() -> None:
    """Show the active agent policy."""
    try:
        policy = _load_policy(strict=True)
    except ValueError as exc:
        raise typer.BadParameter(str(exc))
    typer.echo(json.dumps(policy, indent=2))


@app.command("policy-lint")
def agent_policy_lint() -> None:
    """Validate the policy file and print a normalized representation."""
    policy = _load_policy(strict=True)
    typer.echo(json.dumps({"status": "ok", "policy": policy}, indent=2))


@app.command("policy-set")
def agent_policy_set(
    allow_kind: list[str] = typer.Option(
        None,
        "--allow-kind",
        help="Allowed entry kind for agent retrieval (repeatable)",
        click_type=click.Choice(ALL_ENTRY_TYPES),
    ),
    deny_private_kind: list[str] = typer.Option(
        None,
        "--deny-private-kind",
        help="Kind denied from agent reveal (repeatable)",
        click_type=click.Choice(ALL_ENTRY_TYPES),
    ),
    allow_export_import: bool = typer.Option(
        False,
        "--allow-export-import",
        help="Allow export/import operations in agent mode",
    ),
    safe_output_default: bool = typer.Option(
        True,
        "--safe-output-default/--unsafe-output-default",
        help="Mask sensitive fields in output by default",
    ),
) -> None:
    """Set policy flags used by agent commands (legacy-compatible helper)."""
    policy = _load_policy(strict=False)
    if allow_kind:
        policy["allow_kinds"] = list(allow_kind)
    if deny_private_kind:
        policy["deny_private_reveal"] = list(deny_private_kind)
    policy["allow_export_import"] = bool(allow_export_import)

    policy = _normalize_legacy_policy(policy)
    policy["output"]["safe_output_default"] = bool(safe_output_default)
    _save_policy(policy)
    typer.echo(json.dumps(policy, indent=2))


@app.command("token-issue")
def agent_token_issue(
    name: str = typer.Option("agent", "--name", help="Human-readable token name"),
    scope: list[str] = typer.Option(
        ["read"],
        "--scope",
        help="Allowed operation scope (repeatable, e.g. read/export)",
    ),
    kind: list[str] = typer.Option(
        None,
        "--kind",
        help="Restrict token to entry kinds (repeatable)",
        click_type=click.Choice(ALL_ENTRY_TYPES),
    ),
    label_regex: str = typer.Option(
        ".*",
        "--label-regex",
        help="Regex constraint for entry labels",
    ),
    ttl: int = typer.Option(
        300,
        "--ttl",
        min=1,
        help="Token lifetime in seconds",
    ),
    uses: int = typer.Option(
        1,
        "--uses",
        min=1,
        help="Maximum number of successful uses",
    ),
) -> None:
    """Issue a short-lived scoped token for agent operations."""
    try:
        re.compile(label_regex)
    except re.error as exc:
        raise typer.BadParameter(f"Invalid --label-regex: {exc}") from exc

    scopes = [str(s).strip().lower() for s in scope if str(s).strip()]
    if not scopes:
        raise typer.BadParameter("At least one --scope is required")

    kinds = list(kind or [])
    raw, record = _issue_token_record(name, ttl, scopes, kinds, label_regex, uses)

    store = _load_token_store()
    store.setdefault("version", TOKEN_STORE_VERSION)
    store.setdefault("tokens", [])
    store["tokens"].append(record)
    _save_token_store(store)

    _append_audit_event(
        "agent_token_issued",
        {
            "id": record["id"],
            "name": name,
            "scopes": scopes,
            "kinds": kinds,
            "expires_at_utc": record["expires_at_utc"],
            "uses": uses,
        },
    )

    typer.echo(
        json.dumps(
            {
                "status": "ok",
                "token": raw,
                "token_id": record["id"],
                "name": name,
                "scopes": scopes,
                "kinds": kinds,
                "label_regex": label_regex,
                "expires_at_utc": record["expires_at_utc"],
                "uses_remaining": uses,
            },
            indent=2,
        )
    )


@app.command("token-list")
def agent_token_list(
    show_revoked: bool = typer.Option(False, "--show-revoked")
) -> None:
    """List issued tokens without exposing raw token material."""
    store = _load_token_store()
    tokens = []
    for rec in store.get("tokens", []):
        if not show_revoked and rec.get("revoked_at_utc"):
            continue
        tokens.append(
            {
                "id": rec.get("id"),
                "name": rec.get("name"),
                "created_at_utc": rec.get("created_at_utc"),
                "expires_at_utc": rec.get("expires_at_utc"),
                "revoked_at_utc": rec.get("revoked_at_utc"),
                "scopes": rec.get("scopes", []),
                "kinds": rec.get("kinds", []),
                "label_regex": rec.get("label_regex", ".*"),
                "uses_remaining": rec.get("uses_remaining", 0),
            }
        )
    typer.echo(json.dumps({"status": "ok", "tokens": tokens}, indent=2))


@app.command("token-revoke")
def agent_token_revoke(
    token_id: str = typer.Argument(..., help="Token id to revoke")
) -> None:
    """Revoke an issued token by id."""
    store = _load_token_store()
    now = _utcnow().isoformat()
    changed = False
    for rec in store.get("tokens", []):
        if rec.get("id") == token_id and not rec.get("revoked_at_utc"):
            rec["revoked_at_utc"] = now
            changed = True
            break

    if not changed:
        typer.echo(
            json.dumps({"status": "error", "reason": "token_not_found"}, indent=2)
        )
        raise typer.Exit(1)

    _save_token_store(store)
    _append_audit_event("agent_token_revoked", {"id": token_id})
    typer.echo(json.dumps({"status": "ok", "token_id": token_id}, indent=2))


@app.command("bootstrap-context")
def agent_bootstrap_context(ctx: typer.Context) -> None:
    """Return deterministic context for autonomous agent bootstrap."""
    fingerprint = (ctx.obj or {}).get("fingerprint")
    try:
        policy = _load_policy(strict=True)
        policy = _normalize_policy(policy, strict=False)
        policy_status = "ok"
        policy_error = None
    except ValueError as exc:
        policy = _deny_all_policy()
        policy_status = "invalid"
        policy_error = str(exc)

    payload = {
        "status": "ok",
        "context_schema_version": 1,
        "fingerprint": fingerprint,
        "policy": {
            "status": policy_status,
            "error": policy_error,
            "version": int(policy.get("version", 1)),
            "default_effect": str(policy.get("default_effect", "deny")),
            "rule_count": len(policy.get("rules", [])),
            "safe_output_default": bool(
                policy.get("output", {}).get("safe_output_default", True)
            ),
            "allow_export_import": bool(policy.get("allow_export_import", False)),
        },
        "tokens": _token_posture_summary(),
        "auth_brokers": {
            "supported": ["env", "keyring", "command"],
            "default_agent_get": "env",
            "default_agent_init": "env",
        },
        "commands": {
            "policy": ["agent policy-show", "agent policy-lint", "agent policy-set"],
            "tokens": ["agent token-issue", "agent token-list", "agent token-revoke"],
            "secret_access": ["agent get --fingerprint <fp> <query>"],
            "discovery": ["seedpass capabilities --format json", "seedpass --help"],
        },
    }
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


@app.command("posture-check")
def agent_posture_check(
    fail_on: str = typer.Option(
        "critical",
        "--fail-on",
        help="Minimum severity that returns non-zero exit code",
        click_type=click.Choice(
            ["info", "low", "medium", "high", "critical"], case_sensitive=False
        ),
    ),
    format: str = typer.Option(
        "json",
        "--format",
        help="Output format",
        click_type=click.Choice(["json", "text"], case_sensitive=False),
    ),
) -> None:
    """Run security posture checks for agent configuration and token hygiene."""
    try:
        policy = _load_policy(strict=True)
        policy = _normalize_policy(policy, strict=False)
        policy_status = "ok"
    except ValueError:
        policy = _deny_all_policy()
        policy_status = "invalid"

    findings = _posture_findings(policy, policy_status)
    highest = "info"
    for finding in findings:
        if _severity_rank(finding["severity"]) > _severity_rank(highest):
            highest = finding["severity"]

    payload = {
        "status": "ok",
        "check": "agent_posture",
        "policy_status": policy_status,
        "token_summary": _token_posture_summary(),
        "finding_count": len(findings),
        "highest_severity": highest,
        "fail_on": fail_on.lower(),
        "findings": findings,
    }

    if format.lower() == "json":
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    else:
        typer.echo("SeedPass Agent Posture Check")
        typer.echo(f"policy_status: {payload['policy_status']}")
        typer.echo(f"highest_severity: {payload['highest_severity']}")
        typer.echo(f"finding_count: {payload['finding_count']}")
        if findings:
            typer.echo("")
            for finding in findings:
                typer.echo(
                    f"- [{finding['severity']}] {finding['id']}: {finding['message']}"
                )

    if _severity_rank(highest) >= _severity_rank(fail_on.lower()):
        raise typer.Exit(code=1)


@app.command("get")
def agent_get(
    ctx: typer.Context,
    query: str = typer.Argument(..., help="Entry label or index query"),
    password_env: str = typer.Option(
        "SEEDPASS_PASSWORD", "--password-env", help="Env var containing master password"
    ),
    auth_broker: str = typer.Option(
        "env",
        "--auth-broker",
        help="Non-interactive password broker (env|keyring|command)",
        click_type=click.Choice(["env", "keyring", "command"], case_sensitive=False),
    ),
    broker_service: str = typer.Option(
        "seedpass",
        "--broker-service",
        help="Keyring service name when --auth-broker=keyring",
    ),
    broker_account: Optional[str] = typer.Option(
        None,
        "--broker-account",
        help="Keyring account (defaults to fingerprint)",
    ),
    broker_command: Optional[str] = typer.Option(
        None,
        "--broker-command",
        help="Command that prints password to stdout for --auth-broker=command",
    ),
    token: Optional[str] = typer.Option(
        None,
        "--token",
        help="Scoped agent token. Defaults to SEEDPASS_AGENT_TOKEN env var.",
    ),
    ttl: int = typer.Option(
        30,
        "--ttl",
        min=1,
        help="Lease time in seconds for the returned secret metadata",
    ),
    reveal: bool = typer.Option(
        False,
        "--reveal",
        help="Return plaintext secret instead of redacted output",
    ),
) -> None:
    """Retrieve one secret as JSON with policy enforcement, redaction, and auditing."""
    fingerprint = (ctx.obj or {}).get("fingerprint")
    if not fingerprint:
        raise typer.BadParameter("Specify target profile with --fingerprint.")
    password = _agent_password(
        broker=auth_broker,
        password_env=password_env,
        broker_service=broker_service,
        broker_account=broker_account or str(fingerprint),
        broker_command=broker_command,
    )
    raw_token = token or os.getenv("SEEDPASS_AGENT_TOKEN")

    try:
        policy = _load_policy(strict=True)
        policy = _normalize_policy(policy, strict=False)
    except ValueError as exc:
        payload = {
            "status": "denied",
            "reason": "invalid_policy",
            "detail": str(exc),
        }
        typer.echo(json.dumps(payload, indent=2))
        raise typer.Exit(1)

    pm = PasswordManager(fingerprint=fingerprint, password=password)
    service = EntryService(pm)
    matches = service.search_entries(query)
    if len(matches) != 1:
        payload = {
            "status": "error",
            "reason": "ambiguous_or_missing",
            "match_count": len(matches),
            "matches": [
                {
                    "index": idx,
                    "label": label,
                    "kind": etype.value,
                    "username": username,
                    "url": url,
                    "archived": archived,
                }
                for idx, label, username, url, archived, etype in matches
            ],
        }
        _append_audit_event(
            "agent_secret_access_denied",
            {
                "fingerprint": fingerprint,
                "query": query,
                "reason": "ambiguous_or_missing",
                "match_count": len(matches),
            },
        )
        typer.echo(json.dumps(payload, indent=2))
        raise typer.Exit(1)

    index = matches[0][0]
    entry = service.retrieve_entry(index)
    kind = str(entry.get("type", entry.get("kind", "")))
    label = str(entry.get("label", ""))
    if not kind:
        raise typer.BadParameter("Entry kind missing.")

    entry_path = _build_entry_path(index, kind, label)
    allowed, decision = _policy_decision(
        policy,
        operation="read",
        kind=kind,
        label=label,
        path=entry_path,
        field="secret",
    )
    if not allowed:
        payload = {
            "status": "denied",
            "reason": decision,
            "kind": kind,
            "label": label,
            "index": index,
        }
        _append_audit_event(
            "agent_secret_access_denied",
            {
                "fingerprint": fingerprint,
                "index": index,
                "kind": kind,
                "label": label,
                "reason": decision,
            },
        )
        typer.echo(json.dumps(payload, indent=2))
        raise typer.Exit(1)

    token_meta: dict[str, Any] | None = None
    if raw_token:
        ok, token_reason, token_meta = _validate_token(
            raw_token,
            operation="read",
            kind=kind,
            label=label,
            consume_use=True,
        )
        if not ok:
            payload = {
                "status": "denied",
                "reason": token_reason,
                "kind": kind,
                "label": label,
                "index": index,
            }
            _append_audit_event(
                "agent_secret_access_denied",
                {
                    "fingerprint": fingerprint,
                    "index": index,
                    "kind": kind,
                    "label": label,
                    "reason": token_reason,
                },
            )
            typer.echo(json.dumps(payload, indent=2))
            raise typer.Exit(1)

    secret: Optional[str] = None
    if kind == EntryType.PASSWORD.value:
        secret = service.generate_password(int(entry.get("length", 12)), index)
    elif kind == EntryType.TOTP.value:
        secret = service.get_totp_code(index)
    elif kind == EntryType.KEY_VALUE.value:
        secret = str(entry.get("value", ""))
    else:
        payload = {
            "status": "error",
            "reason": "unsupported_kind_for_agent_get",
            "kind": kind,
        }
        typer.echo(json.dumps(payload, indent=2))
        raise typer.Exit(1)

    now = _utcnow()
    safe_default = bool(policy.get("output", {}).get("safe_output_default", True))
    redacted = safe_default and not reveal
    output_secret = _mask_secret(secret) if redacted else secret

    payload = {
        "status": "ok",
        "fingerprint": fingerprint,
        "index": index,
        "kind": kind,
        "label": label,
        "lease_ttl_sec": ttl,
        "issued_at_utc": now.isoformat(),
        "expires_at_utc": (now + timedelta(seconds=ttl)).isoformat(),
        "safe_output": redacted,
        "secret": output_secret,
        "policy_decision": decision,
    }
    if token_meta is not None:
        payload["token_id"] = token_meta.get("id")
        payload["token_uses_remaining"] = token_meta.get("uses_remaining", 0)

    _append_audit_event(
        "agent_secret_access_granted",
        {
            "fingerprint": fingerprint,
            "index": index,
            "kind": kind,
            "label": label,
            "safe_output": redacted,
            "token_id": (token_meta or {}).get("id"),
        },
    )

    typer.echo(json.dumps(payload, indent=2))
