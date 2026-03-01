from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import difflib
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
from seedpass.core.agent_export_policy import (
    compute_policy_stamp,
    evaluate_full_export,
    evaluate_kind_export,
    verify_filtered_export_package,
)
from seedpass.core.agent_approval import (
    VALID_APPROVAL_ACTIONS,
    approval_required,
    consume_approval,
    issue_approval,
    list_approvals,
    revoke_approval,
)
from seedpass.core.agent_secret_lease import (
    consume_lease,
    issue_lease,
    list_leases,
    revoke_lease,
)
from seedpass.core.agent_identity import (
    create_identity,
    ensure_identity,
    identity_active,
    list_identities,
    revoke_identity,
)
from seedpass.core.agent_job import (
    create_job_profile,
    get_job_profile,
    list_job_profiles,
    revoke_job_profile,
)
from seedpass.core.agent_recovery import (
    list_recovery_drills,
    record_recovery_drill,
    recover_secret,
    split_secret,
)
from seedpass.core.agent_secret_isolation import (
    grant_high_risk_unlock,
    high_risk_factor_configured,
    high_risk_unlocked,
    unlocked_partition_key_tag,
    partition_key_tag_for_factor,
    revoke_high_risk_unlock,
    set_high_risk_factor,
    verify_high_risk_factor,
)
from seedpass.core.high_risk_partition_store import (
    load_partition_entry,
    migrate_high_risk_entries,
)
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

app = typer.Typer(
    help=(
        "Agent-first non-interactive workflows. "
        "Start with `agent bootstrap-context` and `--help` for safe autonomous usage."
    )
)

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
    "secret_isolation": {
        "enabled": True,
        "high_risk_kinds": sorted(PRIVATE_KINDS),
        "unlock_ttl_sec": 300,
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
DEFAULT_AGENT_IDENTITY = "default-agent"
SAFE_AUTOMATION_BROKERS = {"keyring", "command"}


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


def _automation_job_command(
    *,
    fingerprint: str,
    query: str,
    auth_broker: str,
    broker_service: str,
    broker_account: str,
    reveal: bool,
    lease_only: bool,
    lease_ttl: int,
    lease_uses: int,
) -> str:
    parts = [
        "seedpass",
        f"--fingerprint {fingerprint}",
        "agent job-run",
        query,
        f"--auth-broker {auth_broker}",
        f"--broker-service {broker_service}",
        f"--broker-account {broker_account}",
    ]
    if reveal:
        parts.append("--reveal")
    if lease_only:
        parts.extend(
            ["--lease-only", f"--lease-ttl {lease_ttl}", f"--lease-uses {lease_uses}"]
        )
    return " ".join(parts)


def _cron_template(*, schedule: str, command: str) -> str:
    return f"{schedule} {command} >> /var/log/seedpass-agent-job.log 2>&1"


def _systemd_templates(
    *, unit_name: str, schedule: str, command: str
) -> tuple[str, str]:
    service = "\n".join(
        [
            "[Unit]",
            f"Description=SeedPass agent job ({unit_name})",
            "",
            "[Service]",
            "Type=oneshot",
            f"ExecStart={command}",
        ]
    )
    timer = "\n".join(
        [
            "[Unit]",
            f"Description=SeedPass agent timer ({unit_name})",
            "",
            "[Timer]",
            f"OnCalendar={schedule}",
            "Persistent=true",
            "",
            "[Install]",
            "WantedBy=timers.target",
        ]
    )
    return service, timer


def _resolve_secret_for_kind(
    pm: PasswordManager, service: EntryService, entry: dict[str, Any], index: int
) -> str:
    kind = str(entry.get("type", entry.get("kind", "")))
    if kind == EntryType.PASSWORD.value:
        return service.generate_password(int(entry.get("length", 12)), index)
    if kind == EntryType.TOTP.value:
        return service.get_totp_code(index)
    if kind == EntryType.KEY_VALUE.value:
        return str(entry.get("value", ""))
    if kind == EntryType.SEED.value:
        return pm.entry_manager.get_seed_phrase(index, pm.parent_seed)
    if kind == EntryType.MANAGED_ACCOUNT.value:
        return pm.entry_manager.get_managed_account_seed(index, pm.parent_seed)
    if kind == EntryType.SSH.value:
        secret, _pub = pm.entry_manager.get_ssh_key_pair(index, pm.parent_seed)
        return secret
    if kind == EntryType.PGP.value:
        secret, _fp = pm.entry_manager.get_pgp_key(index, pm.parent_seed)
        return secret
    if kind == EntryType.NOSTR.value:
        _npub, secret = pm.entry_manager.get_nostr_key_pair(index, pm.parent_seed)
        return secret
    raise ValueError("unsupported_kind_for_agent_get")


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
        "secret_isolation": {
            "enabled": True,
            "high_risk_kinds": sorted(PRIVATE_KINDS),
            "unlock_ttl_sec": 300,
        },
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
    isolation_cfg = data.get("secret_isolation")

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
    secret_isolation = dict(DEFAULT_POLICY["secret_isolation"])
    if isinstance(isolation_cfg, dict):
        secret_isolation["enabled"] = bool(isolation_cfg.get("enabled", True))
        raw_high_risk = isolation_cfg.get("high_risk_kinds")
        if isinstance(raw_high_risk, list):
            secret_isolation["high_risk_kinds"] = [
                str(v).strip().lower()
                for v in raw_high_risk
                if str(v).strip().lower() in PRIVATE_KINDS
            ]
        raw_unlock_ttl = isolation_cfg.get("unlock_ttl_sec")
        if raw_unlock_ttl is not None:
            try:
                ttl = int(raw_unlock_ttl)
                if ttl > 0:
                    secret_isolation["unlock_ttl_sec"] = ttl
            except (TypeError, ValueError):
                pass
    policy["secret_isolation"] = secret_isolation
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

    approvals_cfg = policy.get("approvals")
    if not isinstance(approvals_cfg, dict):
        if strict and "approvals" in data:
            raise ValueError("approvals must be an object")
        approvals_cfg = {}
    raw_require_for = approvals_cfg.get(
        "require_for", DEFAULT_POLICY["approvals"]["require_for"]
    )
    if not isinstance(raw_require_for, list):
        if strict:
            raise ValueError("approvals.require_for must be a list")
        raw_require_for = DEFAULT_POLICY["approvals"]["require_for"]
    require_for: list[str] = []
    for value in raw_require_for:
        action = str(value).strip().lower()
        if action in VALID_APPROVAL_ACTIONS and action not in require_for:
            require_for.append(action)
        elif strict:
            raise ValueError(f"invalid approval action: {value}")
    policy["approvals"] = {"require_for": require_for}

    isolation_cfg = policy.get("secret_isolation")
    if not isinstance(isolation_cfg, dict):
        if strict and "secret_isolation" in data:
            raise ValueError("secret_isolation must be an object")
        isolation_cfg = {}
    raw_high_risk = isolation_cfg.get(
        "high_risk_kinds", DEFAULT_POLICY["secret_isolation"]["high_risk_kinds"]
    )
    if not isinstance(raw_high_risk, list):
        if strict:
            raise ValueError("secret_isolation.high_risk_kinds must be a list")
        raw_high_risk = DEFAULT_POLICY["secret_isolation"]["high_risk_kinds"]
    high_risk_kinds: list[str] = []
    for value in raw_high_risk:
        kind = str(value).strip().lower()
        if kind in PRIVATE_KINDS and kind not in high_risk_kinds:
            high_risk_kinds.append(kind)
        elif strict:
            raise ValueError(f"invalid secret isolation kind: {value}")
    unlock_ttl_sec = int(
        isolation_cfg.get(
            "unlock_ttl_sec", DEFAULT_POLICY["secret_isolation"]["unlock_ttl_sec"]
        )
    )
    if unlock_ttl_sec < 1:
        if strict:
            raise ValueError("secret_isolation.unlock_ttl_sec must be >= 1")
        unlock_ttl_sec = int(DEFAULT_POLICY["secret_isolation"]["unlock_ttl_sec"])
    policy["secret_isolation"] = {
        "enabled": bool(isolation_cfg.get("enabled", True)),
        "high_risk_kinds": high_risk_kinds,
        "unlock_ttl_sec": unlock_ttl_sec,
    }

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


def _load_policy_from_file(path: Path, *, strict: bool = True) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError("agent policy file is not valid JSON") from exc
    if not isinstance(data, dict):
        raise ValueError("agent policy file must be a JSON object")
    return _normalize_policy(data, strict=strict)


def _policy_json_lines(policy: dict[str, Any]) -> list[str]:
    return json.dumps(policy, indent=2, sort_keys=True).splitlines()


def _policy_full_hash(policy: dict[str, Any]) -> str:
    canonical = json.dumps(
        policy, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _policy_diff_summary(
    current: dict[str, Any], candidate: dict[str, Any]
) -> dict[str, Any]:
    current_rule_map = {str(r.get("id", "")): r for r in current.get("rules", [])}
    candidate_rule_map = {str(r.get("id", "")): r for r in candidate.get("rules", [])}

    current_ids = {k for k in current_rule_map if k}
    candidate_ids = {k for k in candidate_rule_map if k}
    added = sorted(candidate_ids - current_ids)
    removed = sorted(current_ids - candidate_ids)
    modified = sorted(
        rid
        for rid in (current_ids & candidate_ids)
        if current_rule_map[rid] != candidate_rule_map[rid]
    )

    return {
        "default_effect_changed": current.get("default_effect")
        != candidate.get("default_effect"),
        "export_allow_full_vault_changed": bool(
            current.get("export", {}).get("allow_full_vault", False)
        )
        != bool(candidate.get("export", {}).get("allow_full_vault", False)),
        "safe_output_default_changed": bool(
            current.get("output", {}).get("safe_output_default", True)
        )
        != bool(candidate.get("output", {}).get("safe_output_default", True)),
        "rules_added": added,
        "rules_removed": removed,
        "rules_modified": modified,
    }


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
    identity_id: str,
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
        "identity_id": str(identity_id),
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

        identity_id = str(rec.get("identity_id", "")).strip()
        if not identity_id:
            return False, "token_identity_missing", None
        if not identity_active(identity_id):
            return False, "token_identity_revoked", None

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


def _high_risk_lock_required(policy: dict[str, Any], kind: str) -> bool:
    isolation_cfg = policy.get("secret_isolation", {})
    if not isinstance(isolation_cfg, dict):
        return False
    if not bool(isolation_cfg.get("enabled", True)):
        return False
    kinds = isolation_cfg.get("high_risk_kinds", [])
    if not isinstance(kinds, list):
        return False
    return str(kind).lower() in {str(v).lower() for v in kinds}


def _hydrate_partition_entry_if_needed(
    pm: PasswordManager,
    *,
    fingerprint: str,
    index: int,
    entry: dict[str, Any],
) -> dict[str, Any]:
    if str(entry.get("partition", "")).strip().lower() != "high_risk":
        return entry
    tag = unlocked_partition_key_tag(fingerprint=str(fingerprint))
    if not tag:
        raise ValueError("policy_deny:high_risk_locked")
    loaded = load_partition_entry(Path(pm.fingerprint_dir), tag, int(index))
    if not isinstance(loaded, dict):
        raise ValueError("high_risk_partition_entry_missing")
    return loaded


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

    require_for = {
        str(v).strip().lower()
        for v in policy.get("approvals", {}).get("require_for", [])
        if str(v).strip()
    }
    required_approvals = {"export", "reveal_parent_seed", "private_key_retrieval"}
    missing_approvals = sorted(list(required_approvals - require_for))
    if missing_approvals:
        findings.append(
            {
                "id": "approvals_missing_required_actions",
                "severity": "high",
                "message": f"Approval gate policy is missing required actions: {', '.join(missing_approvals)}.",
                "remediation": "Require approvals for export, reveal_parent_seed, and private_key_retrieval.",
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

    isolation_cfg = policy.get("secret_isolation", {})
    unlock_ttl_sec = int(isolation_cfg.get("unlock_ttl_sec", 300) or 300)
    if bool(isolation_cfg.get("enabled", True)) and unlock_ttl_sec > 1800:
        findings.append(
            {
                "id": "high_risk_unlock_ttl_too_long",
                "severity": "medium",
                "message": f"High-risk unlock TTL is {unlock_ttl_sec}s (>1800s).",
                "remediation": "Reduce secret_isolation.unlock_ttl_sec to 1800 seconds or lower.",
            }
        )

    allows_private_read = False
    for rule in policy.get("rules", []):
        if str(rule.get("effect", "")).lower() != "allow":
            continue
        ops = {str(v).lower() for v in rule.get("operations", [])}
        if "read" not in ops:
            continue
        kinds = {str(v).lower() for v in rule.get("kinds", [])}
        if kinds.intersection(PRIVATE_KINDS):
            allows_private_read = True
        fields = {str(v).lower() for v in rule.get("fields", [])}
        label_regex = str(rule.get("label_regex", ".*"))
        path_regex = str(rule.get("path_regex", ".*"))
        if (
            "read" in ops
            and "secret" in fields
            and (not kinds or len(kinds) >= len(ALL_ENTRY_TYPES))
            and label_regex in {".*", "^.*$"}
            and path_regex in {"^entry/.*$", ".*", "^.*$"}
        ):
            findings.append(
                {
                    "id": "over_permissive_read_rule",
                    "severity": "high",
                    "message": f"Policy allow rule '{rule.get('id', 'rule')}' broadly permits secret reads.",
                    "remediation": "Scope read rules by kind, label_regex, and field exposure.",
                }
            )
    if not bool(isolation_cfg.get("enabled", True)):
        findings.append(
            {
                "id": "secret_isolation_disabled",
                "severity": "high",
                "message": "Secret class isolation is disabled for high-risk kinds.",
                "remediation": "Enable secret_isolation and require separate high-risk unlock.",
            }
        )
    elif allows_private_read and not high_risk_factor_configured():
        findings.append(
            {
                "id": "high_risk_factor_not_configured",
                "severity": "medium",
                "message": "High-risk unlock factor is not configured.",
                "remediation": "Run `seedpass agent high-risk-factor-set` before enabling autonomous private-key retrieval.",
            }
        )
    elif allows_private_read and "private_key_retrieval" not in require_for:
        findings.append(
            {
                "id": "private_read_without_approval_gate",
                "severity": "high",
                "message": "Policy allows private-kind reads without private_key_retrieval approval gate.",
                "remediation": "Add private_key_retrieval to approvals.require_for.",
            }
        )

    store = _load_token_store()
    now = _utcnow()
    long_lived = 0
    broad_scope = 0
    missing_identity = 0
    revoked_identity_tokens = 0
    overdue_rotation = 0
    active_identities = list_identities(include_revoked=False)
    identities_by_id = {str(rec.get("id", "")): rec for rec in active_identities}
    high_rotation_days = [
        str(rec.get("id", ""))
        for rec in active_identities
        if int(rec.get("rotation_days", 30) or 30) > 90
    ]
    if high_rotation_days:
        findings.append(
            {
                "id": "identity_rotation_window_too_long",
                "severity": "medium",
                "message": f"{len(high_rotation_days)} identity profile(s) have rotation_days > 90.",
                "remediation": "Set identity rotation_days to 90 or less for tighter credential rotation.",
            }
        )

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

        identity_id = str(rec.get("identity_id", "")).strip()
        if not identity_id:
            missing_identity += 1
        elif not identity_active(identity_id):
            revoked_identity_tokens += 1
        else:
            identity_rec = identities_by_id.get(identity_id)
            if identity_rec and created:
                try:
                    rotation_days = int(identity_rec.get("rotation_days", 30) or 30)
                    age_days = (
                        _utcnow() - _parse_iso8601(created)
                    ).total_seconds() / 86400
                    if age_days > rotation_days:
                        overdue_rotation += 1
                except Exception:
                    pass

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
    if missing_identity:
        findings.append(
            {
                "id": "tokens_missing_identity",
                "severity": "medium",
                "message": f"{missing_identity} token(s) are not bound to an agent identity.",
                "remediation": "Reissue tokens with --identity-id and revoke legacy unbound tokens.",
            }
        )
    if revoked_identity_tokens:
        findings.append(
            {
                "id": "tokens_for_revoked_identity",
                "severity": "high",
                "message": f"{revoked_identity_tokens} token(s) reference revoked or missing identities.",
                "remediation": "Revoke affected tokens and rotate new tokens under active identities.",
            }
        )
    if overdue_rotation:
        findings.append(
            {
                "id": "token_rotation_overdue",
                "severity": "medium",
                "message": f"{overdue_rotation} active token(s) exceed identity rotation policy window.",
                "remediation": "Rotate overdue tokens and reissue under current identity policy.",
            }
        )

    return findings


def _runtime_config_findings(pm: PasswordManager) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    cfg_mgr = getattr(pm, "config_manager", None)
    if cfg_mgr is None:
        return findings

    try:
        if bool(cfg_mgr.get_quick_unlock()):
            findings.append(
                {
                    "id": "quick_unlock_enabled",
                    "severity": "high",
                    "message": "Quick unlock is enabled for the profile.",
                    "remediation": "Disable quick unlock for unattended or shared environments.",
                }
            )
    except Exception:
        pass

    try:
        kdf_mode = str(cfg_mgr.get_kdf_mode()).lower()
    except Exception:
        kdf_mode = "pbkdf2"
    try:
        kdf_iterations = int(cfg_mgr.get_kdf_iterations())
    except Exception:
        kdf_iterations = 0
    if kdf_mode == "pbkdf2" and kdf_iterations < int(
        getattr(ConfigManager, "DEFAULT_PBKDF2_ITERATIONS", 200_000)
    ):
        findings.append(
            {
                "id": "weak_kdf_iterations",
                "severity": "high",
                "message": f"PBKDF2 iterations are set to {kdf_iterations}, below policy floor.",
                "remediation": "Increase kdf_iterations to at least the default floor.",
            }
        )

    try:
        parts = cfg_mgr.get_secret_class_partitions()
        high_risk = parts.get("high_risk", {}) if isinstance(parts, dict) else {}
        if bool(high_risk.get("separate_factor_required", True)) and bool(
            high_risk.get("unlocked", False)
        ):
            findings.append(
                {
                    "id": "high_risk_partition_persistently_unlocked",
                    "severity": "high",
                    "message": "High-risk partition is marked unlocked in profile config.",
                    "remediation": "Lock high-risk partition by default and require step-up unlock per session.",
                }
            )
    except Exception:
        pass

    return findings


def _remediation_actions(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    guidance: dict[str, dict[str, Any]] = {
        "policy_invalid": {
            "title": "Fix invalid policy file",
            "commands": [
                "seedpass agent policy-lint",
                "seedpass agent policy-review --file <candidate.json>",
                "seedpass agent policy-apply --file <candidate.json>",
            ],
        },
        "policy_default_allow": {
            "title": "Set secure policy default",
            "commands": ["seedpass agent policy-set --safe-output-default"],
            "notes": ["Set `default_effect` to `deny` and add explicit allow rules."],
        },
        "approvals_missing_required_actions": {
            "title": "Enforce approval gates for risky actions",
            "commands": ["seedpass agent policy-review --file <candidate.json>"],
            "notes": [
                "Ensure approvals.require_for includes export, reveal_parent_seed, and private_key_retrieval."
            ],
        },
        "safe_output_disabled": {
            "title": "Enable safe output redaction",
            "commands": ["seedpass agent policy-set --safe-output-default"],
        },
        "export_import_allowed": {
            "title": "Disable broad export/import for agent profiles",
            "commands": ["seedpass agent policy-review --file <candidate.json>"],
            "notes": ["Set export.allow_full_vault=false and keep allow_export_import=false."],
        },
        "secret_isolation_disabled": {
            "title": "Enable high-risk secret isolation",
            "commands": [
                "seedpass agent high-risk-factor-set --factor-env SEEDPASS_HIGH_RISK_FACTOR",
                "seedpass agent policy-review --file <candidate.json>",
            ],
        },
        "high_risk_factor_not_configured": {
            "title": "Configure high-risk unlock factor",
            "commands": [
                "seedpass agent high-risk-factor-set --factor-env SEEDPASS_HIGH_RISK_FACTOR"
            ],
        },
        "high_risk_unlock_ttl_too_long": {
            "title": "Reduce high-risk unlock TTL",
            "commands": ["seedpass agent policy-review --file <candidate.json>"],
            "notes": ["Set secret_isolation.unlock_ttl_sec <= 1800."],
        },
        "over_permissive_read_rule": {
            "title": "Narrow broad secret-read policy rules",
            "commands": ["seedpass agent policy-review --file <candidate.json>"],
        },
        "private_read_without_approval_gate": {
            "title": "Require approval for private key retrieval",
            "commands": ["seedpass agent policy-review --file <candidate.json>"],
        },
        "quick_unlock_enabled": {
            "title": "Disable quick unlock in runtime config",
            "commands": ["seedpass config set quick_unlock false"],
        },
        "weak_kdf_iterations": {
            "title": "Increase KDF iteration strength",
            "commands": ["seedpass config set kdf_iterations 200000"],
        },
        "high_risk_partition_persistently_unlocked": {
            "title": "Lock high-risk partition by default",
            "commands": ["seedpass --fingerprint <fp> agent high-risk-lock"],
        },
        "long_lived_tokens": {
            "title": "Shorten token TTL and rotate",
            "commands": [
                "seedpass agent token-list",
                "seedpass agent token-revoke <token_id>",
                "seedpass agent token-issue --ttl 3600 --uses 1",
            ],
        },
        "overbroad_token_scopes": {
            "title": "Reduce token scopes",
            "commands": [
                "seedpass agent token-revoke <token_id>",
                "seedpass agent token-issue --scope read --kinds password --uses 1",
            ],
        },
        "tokens_missing_identity": {
            "title": "Bind tokens to active identities",
            "commands": [
                "seedpass agent identity-create --id <identity> --owner <team>",
                "seedpass agent token-issue --identity-id <identity>",
            ],
        },
        "tokens_for_revoked_identity": {
            "title": "Rotate tokens from revoked identities",
            "commands": [
                "seedpass agent token-revoke <token_id>",
                "seedpass agent token-issue --identity-id <active_identity>",
            ],
        },
        "identity_rotation_window_too_long": {
            "title": "Tighten identity rotation policy",
            "commands": ["seedpass agent identity-create --id <id> --rotation-days 30"],
            "notes": ["Recreate identity metadata with a shorter rotation window."],
        },
        "token_rotation_overdue": {
            "title": "Rotate overdue active tokens",
            "commands": [
                "seedpass agent token-list",
                "seedpass agent token-revoke <token_id>",
                "seedpass agent token-issue --identity-id <identity>",
            ],
        },
    }
    actions: list[dict[str, Any]] = []
    seen: set[str] = set()
    for finding in findings:
        fid = str(finding.get("id", ""))
        if not fid or fid in seen:
            continue
        seen.add(fid)
        base = guidance.get(fid)
        if not base:
            continue
        action = {
            "finding_id": fid,
            "title": base["title"],
            "commands": base["commands"],
        }
        if "notes" in base:
            action["notes"] = base["notes"]
        actions.append(action)
    return actions


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
        "next_steps": [
            "seedpass --fingerprint <fp> vault unlock --auth-broker keyring",
            "seedpass capabilities --format json",
            "seedpass --fingerprint <fp> agent bootstrap-context",
        ],
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
def agent_policy_lint(
    file: Optional[Path] = typer.Option(
        None, "--file", help="Policy file to lint (defaults to active agent policy)"
    ),
    format: str = typer.Option(
        "json",
        "--format",
        help="Output format",
        click_type=click.Choice(["json", "text"], case_sensitive=False),
    ),
) -> None:
    """Validate a policy file and emit deterministic normalized output."""
    if file is None:
        policy = _load_policy(strict=True)
        path = _policy_path()
    else:
        policy = _load_policy_from_file(file, strict=True)
        path = file
    policy_stamp = compute_policy_stamp(policy)
    policy_hash = _policy_full_hash(policy)
    payload = {
        "status": "ok",
        "path": str(path),
        "policy_stamp": policy_stamp,
        "policy_hash": policy_hash,
        "policy": policy,
    }
    if format.lower() == "text":
        typer.echo("policy lint: ok")
        typer.echo(f"path: {payload['path']}")
        typer.echo(f"policy_stamp: {policy_stamp}")
        typer.echo(f"policy_hash: {policy_hash}")
        typer.echo(f"rules: {len(policy.get('rules', []))}")
        return
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


@app.command("policy-review")
def agent_policy_review(
    file: Path = typer.Option(..., "--file", help="Candidate policy JSON file"),
    format: str = typer.Option(
        "json",
        "--format",
        help="Output format",
        click_type=click.Choice(["json", "text"], case_sensitive=False),
    ),
) -> None:
    """Compare active policy to candidate policy for change review."""
    current = _load_policy(strict=False)
    candidate = _load_policy_from_file(file, strict=True)
    current_lines = _policy_json_lines(current)
    candidate_lines = _policy_json_lines(candidate)
    diff_lines = list(
        difflib.unified_diff(
            current_lines,
            candidate_lines,
            fromfile="active_policy",
            tofile=str(file),
            lineterm="",
        )
    )
    diff_summary = _policy_diff_summary(current, candidate)
    findings = _posture_findings(candidate, "ok")
    risky_findings = [
        f for f in findings if _severity_rank(f.get("severity", "info")) >= 3
    ]
    payload = {
        "status": "ok",
        "changed": current != candidate,
        "candidate_path": str(file),
        "current_policy_stamp": compute_policy_stamp(current),
        "candidate_policy_stamp": compute_policy_stamp(candidate),
        "current_policy_hash": _policy_full_hash(current),
        "candidate_policy_hash": _policy_full_hash(candidate),
        "diff_summary": diff_summary,
        "risky_finding_count": len(risky_findings),
        "risky_findings": risky_findings,
        "diff": diff_lines,
    }
    if format.lower() == "text":
        typer.echo(f"policy changed: {payload['changed']}")
        typer.echo(f"candidate: {payload['candidate_path']}")
        typer.echo(f"current stamp: {payload['current_policy_stamp']}")
        typer.echo(f"candidate stamp: {payload['candidate_policy_stamp']}")
        typer.echo(f"risky findings: {payload['risky_finding_count']}")
        if diff_summary["rules_added"]:
            typer.echo(f"rules added: {', '.join(diff_summary['rules_added'])}")
        if diff_summary["rules_removed"]:
            typer.echo(f"rules removed: {', '.join(diff_summary['rules_removed'])}")
        if diff_summary["rules_modified"]:
            typer.echo(f"rules modified: {', '.join(diff_summary['rules_modified'])}")
        if diff_lines:
            typer.echo("diff:")
            for line in diff_lines:
                typer.echo(line)
        return
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


@app.command("policy-apply")
def agent_policy_apply(
    file: Path = typer.Option(..., "--file", help="Candidate policy JSON file"),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Validate and review candidate without saving"
    ),
    allow_risky: bool = typer.Option(
        False,
        "--allow-risky",
        help="Allow apply when review detects high-risk findings",
    ),
) -> None:
    """Apply a reviewed policy file with optional risk gate."""
    current = _load_policy(strict=False)
    candidate = _load_policy_from_file(file, strict=True)
    findings = _posture_findings(candidate, "ok")
    risky_findings = [
        f for f in findings if _severity_rank(f.get("severity", "info")) >= 3
    ]
    changed = current != candidate
    payload = {
        "status": "ok",
        "changed": changed,
        "dry_run": bool(dry_run),
        "candidate_path": str(file),
        "candidate_policy_stamp": compute_policy_stamp(candidate),
        "candidate_policy_hash": _policy_full_hash(candidate),
        "risky_finding_count": len(risky_findings),
        "risky_findings": risky_findings,
    }
    if risky_findings and not allow_risky:
        payload["status"] = "denied"
        payload["reason"] = "risky_policy_change_requires_allow_risky"
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        raise typer.Exit(1)
    if not dry_run and changed:
        _save_policy(candidate)
        payload["applied"] = True
        _append_audit_event(
            "agent_policy_applied",
            {
                "candidate_path": str(file),
                "policy_stamp": payload["candidate_policy_stamp"],
                "policy_hash": payload["candidate_policy_hash"],
                "risky_finding_count": payload["risky_finding_count"],
            },
        )
    else:
        payload["applied"] = False
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


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


@app.command("identity-create")
def agent_identity_create(
    identity_id: str = typer.Option(..., "--id", help="Stable agent identity id"),
    owner: str = typer.Option("unowned", "--owner", help="Owner/team for the identity"),
    policy_binding: str = typer.Option(
        "default", "--policy-binding", help="Named policy binding tag"
    ),
    rotation_days: int = typer.Option(
        30, "--rotation-days", min=1, help="Target token rotation interval in days"
    ),
) -> None:
    """Create a first-class agent identity."""
    try:
        rec = create_identity(
            identity_id=identity_id,
            owner=owner,
            policy_binding=policy_binding,
            rotation_days=rotation_days,
        )
    except ValueError as exc:
        reason = str(exc)
        payload = {"status": "error", "reason": reason, "id": identity_id}
        typer.echo(json.dumps(payload, indent=2))
        raise typer.Exit(1)
    _append_audit_event(
        "agent_identity_created",
        {
            "id": rec.get("id"),
            "owner": rec.get("owner"),
            "policy_binding": rec.get("policy_binding"),
            "rotation_days": rec.get("rotation_days"),
        },
    )
    typer.echo(json.dumps({"status": "ok", "identity": rec}, indent=2, sort_keys=True))


@app.command("identity-list")
def agent_identity_list(
    show_revoked: bool = typer.Option(False, "--show-revoked")
) -> None:
    """List registered agent identities."""
    typer.echo(
        json.dumps(
            {
                "status": "ok",
                "identities": list_identities(include_revoked=show_revoked),
            },
            indent=2,
            sort_keys=True,
        )
    )


@app.command("identity-revoke")
def agent_identity_revoke(
    identity_id: str = typer.Argument(..., help="Identity id")
) -> None:
    """Revoke an agent identity."""
    if not revoke_identity(identity_id):
        payload = {"status": "error", "reason": "identity_not_found", "id": identity_id}
        typer.echo(json.dumps(payload, indent=2))
        raise typer.Exit(1)
    _append_audit_event("agent_identity_revoked", {"id": identity_id})
    typer.echo(json.dumps({"status": "ok", "id": identity_id}, indent=2))


@app.command("high-risk-factor-set")
def agent_high_risk_factor_set(
    factor_env: str = typer.Option(
        "SEEDPASS_HIGH_RISK_FACTOR",
        "--factor-env",
        help="Env var containing high-risk unlock factor when --auth-broker=env",
    ),
    auth_broker: str = typer.Option(
        "env",
        "--auth-broker",
        help="Factor source (env|keyring|command)",
        click_type=click.Choice(["env", "keyring", "command"], case_sensitive=False),
    ),
    broker_service: str = typer.Option(
        "seedpass",
        "--broker-service",
        help="Keyring service name when --auth-broker=keyring",
    ),
    broker_account: str = typer.Option(
        "high-risk-factor",
        "--broker-account",
        help="Keyring account identity for factor retrieval",
    ),
    broker_command: Optional[str] = typer.Option(
        None,
        "--broker-command",
        help="Command that prints factor to stdout for --auth-broker=command",
    ),
) -> None:
    """Configure the separate high-risk unlock factor."""
    factor = _agent_password(
        broker=auth_broker,
        password_env=factor_env,
        broker_service=broker_service,
        broker_account=broker_account,
        broker_command=broker_command,
    )
    if not factor:
        raise typer.BadParameter("High-risk factor cannot be empty.")
    set_high_risk_factor(factor)
    _append_audit_event("agent_high_risk_factor_set", {"configured": True})
    typer.echo(json.dumps({"status": "ok", "configured": True}, indent=2))


@app.command("high-risk-unlock")
def agent_high_risk_unlock(
    ctx: typer.Context,
    ttl: Optional[int] = typer.Option(
        None,
        "--ttl",
        min=1,
        help="Unlock TTL in seconds (defaults to policy secret_isolation.unlock_ttl_sec)",
    ),
    factor_env: str = typer.Option(
        "SEEDPASS_HIGH_RISK_FACTOR",
        "--factor-env",
        help="Env var containing high-risk unlock factor when --auth-broker=env",
    ),
    auth_broker: str = typer.Option(
        "env",
        "--auth-broker",
        help="Factor source (env|keyring|command)",
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
        help="Keyring account (defaults to <fingerprint>:high-risk)",
    ),
    broker_command: Optional[str] = typer.Option(
        None,
        "--broker-command",
        help="Command that prints factor to stdout for --auth-broker=command",
    ),
) -> None:
    """Unlock access to high-risk secret classes for the active fingerprint."""
    fingerprint = (ctx.obj or {}).get("fingerprint")
    if not fingerprint:
        raise typer.BadParameter("Specify target profile with --fingerprint.")
    if not high_risk_factor_configured():
        payload = {"status": "error", "reason": "high_risk_factor_not_configured"}
        typer.echo(json.dumps(payload, indent=2))
        raise typer.Exit(1)
    factor = _agent_password(
        broker=auth_broker,
        password_env=factor_env,
        broker_service=broker_service,
        broker_account=broker_account or f"{fingerprint}:high-risk",
        broker_command=broker_command,
    )
    if not verify_high_risk_factor(factor):
        payload = {"status": "denied", "reason": "high_risk_factor_invalid"}
        typer.echo(json.dumps(payload, indent=2))
        raise typer.Exit(1)
    try:
        key_tag = partition_key_tag_for_factor(factor)
    except ValueError as exc:
        payload = {"status": "denied", "reason": str(exc)}
        typer.echo(json.dumps(payload, indent=2))
        raise typer.Exit(1)

    policy = _load_policy(strict=False)
    isolation_cfg = policy.get("secret_isolation", {})
    default_ttl = int(isolation_cfg.get("unlock_ttl_sec", 300))
    session = grant_high_risk_unlock(
        fingerprint=str(fingerprint),
        ttl_seconds=int(ttl or default_ttl),
        partition_key_tag=key_tag,
    )
    _append_audit_event(
        "agent_high_risk_unlocked",
        {
            "fingerprint": fingerprint,
            "expires_at_utc": session.get("expires_at_utc"),
            "ttl_seconds": int(ttl or default_ttl),
        },
    )
    typer.echo(
        json.dumps(
            {
                "status": "ok",
                "fingerprint": fingerprint,
                "expires_at_utc": session.get("expires_at_utc"),
            },
            indent=2,
            sort_keys=True,
        )
    )


@app.command("high-risk-lock")
def agent_high_risk_lock(ctx: typer.Context) -> None:
    """Revoke active high-risk unlock session for the active fingerprint."""
    fingerprint = (ctx.obj or {}).get("fingerprint")
    if not fingerprint:
        raise typer.BadParameter("Specify target profile with --fingerprint.")
    changed = revoke_high_risk_unlock(fingerprint=str(fingerprint))
    _append_audit_event(
        "agent_high_risk_locked",
        {"fingerprint": fingerprint, "changed": bool(changed)},
    )
    typer.echo(
        json.dumps(
            {"status": "ok", "fingerprint": fingerprint, "locked": bool(changed)},
            indent=2,
            sort_keys=True,
        )
    )


@app.command("high-risk-status")
def agent_high_risk_status(ctx: typer.Context) -> None:
    """Show high-risk unlock session status for the active fingerprint."""
    fingerprint = (ctx.obj or {}).get("fingerprint")
    if not fingerprint:
        raise typer.BadParameter("Specify target profile with --fingerprint.")
    unlocked, expires_at = high_risk_unlocked(fingerprint=str(fingerprint))
    payload = {
        "status": "ok",
        "fingerprint": fingerprint,
        "factor_configured": high_risk_factor_configured(),
        "unlocked": bool(unlocked),
        "expires_at_utc": expires_at or None,
        "partition_key_tag_present": bool(
            unlocked_partition_key_tag(fingerprint=str(fingerprint))
        ),
    }
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


@app.command("high-risk-partition-migrate")
def agent_high_risk_partition_migrate(
    ctx: typer.Context,
    password_env: str = typer.Option(
        "SEEDPASS_PASSWORD", "--password-env", help="Env var containing master password"
    ),
    auth_broker: str = typer.Option(
        "env",
        "--auth-broker",
        help="Password source (env|keyring|command)",
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
    factor_env: str = typer.Option(
        "SEEDPASS_HIGH_RISK_FACTOR",
        "--factor-env",
        help="Env var containing high-risk factor",
    ),
    factor_broker: str = typer.Option(
        "env",
        "--factor-broker",
        help="Factor source (env|keyring|command)",
        click_type=click.Choice(["env", "keyring", "command"], case_sensitive=False),
    ),
    factor_broker_service: str = typer.Option(
        "seedpass",
        "--factor-broker-service",
        help="Keyring service name for high-risk factor broker",
    ),
    factor_broker_account: Optional[str] = typer.Option(
        None,
        "--factor-broker-account",
        help="Keyring account for factor (defaults to <fingerprint>:high-risk)",
    ),
    factor_broker_command: Optional[str] = typer.Option(
        None,
        "--factor-broker-command",
        help="Command that prints high-risk factor to stdout",
    ),
) -> None:
    """Move high-risk entries from primary index into encrypted high-risk partition."""
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
    factor = _agent_password(
        broker=factor_broker,
        password_env=factor_env,
        broker_service=factor_broker_service,
        broker_account=factor_broker_account or f"{fingerprint}:high-risk",
        broker_command=factor_broker_command,
    )
    if not verify_high_risk_factor(factor):
        payload = {"status": "denied", "reason": "high_risk_factor_invalid"}
        typer.echo(json.dumps(payload, indent=2))
        raise typer.Exit(1)
    try:
        key_tag = partition_key_tag_for_factor(factor)
    except ValueError as exc:
        payload = {"status": "denied", "reason": str(exc)}
        typer.echo(json.dumps(payload, indent=2))
        raise typer.Exit(1)

    pm = PasswordManager(fingerprint=fingerprint, password=password)
    policy = _load_policy(strict=False)
    kinds = {
        str(v).strip().lower()
        for v in policy.get("secret_isolation", {}).get(
            "high_risk_kinds", PRIVATE_KINDS
        )
        if str(v).strip().lower()
    }
    result = migrate_high_risk_entries(
        vault=pm.vault,
        fingerprint_dir=Path(pm.fingerprint_dir),
        partition_key_tag=key_tag,
        high_risk_kinds=kinds,
    )
    _append_audit_event(
        "agent_high_risk_partition_migrated",
        {
            "fingerprint": fingerprint,
            "moved_count": int(result.get("moved_count", 0)),
            "partition_file": result.get("partition_file"),
        },
    )
    typer.echo(json.dumps({"status": "ok", **result}, indent=2, sort_keys=True))


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
    identity_id: str = typer.Option(
        DEFAULT_AGENT_IDENTITY,
        "--identity-id",
        help="Agent identity bound to this token",
    ),
    identity_owner: str = typer.Option(
        "system",
        "--identity-owner",
        help="Owner used when auto-creating identity",
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
    identity = ensure_identity(
        identity_id,
        owner=identity_owner,
        policy_binding="default",
        rotation_days=30,
    )
    if identity.get("revoked_at_utc"):
        payload = {
            "status": "error",
            "reason": "identity_revoked",
            "identity_id": identity_id,
        }
        typer.echo(json.dumps(payload, indent=2))
        raise typer.Exit(1)
    raw, record = _issue_token_record(
        name,
        ttl,
        scopes,
        kinds,
        label_regex,
        uses,
        str(identity.get("id", identity_id)),
    )

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
            "identity_id": record["identity_id"],
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
                "identity_id": record["identity_id"],
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
                "identity_id": rec.get("identity_id"),
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


@app.command("approval-issue")
def agent_approval_issue(
    action: str = typer.Option(
        "export",
        "--action",
        help="Action requiring approval",
        click_type=click.Choice(
            sorted(list(VALID_APPROVAL_ACTIONS)),
            case_sensitive=False,
        ),
    ),
    ttl: int = typer.Option(
        300,
        "--ttl",
        min=1,
        help="Approval lifetime in seconds",
    ),
    uses: int = typer.Option(
        1,
        "--uses",
        min=1,
        help="Number of successful uses before invalidation",
    ),
    resource: str = typer.Option(
        "*",
        "--resource",
        help="Resource scope for approval (e.g. vault:full)",
    ),
    issued_by: str = typer.Option(
        "manual",
        "--issued-by",
        help="Issuer identity for audit metadata",
    ),
) -> None:
    """Issue a short-lived approval grant for risky actions."""
    rec = issue_approval(
        action=action.strip().lower(),
        ttl_seconds=ttl,
        uses=uses,
        resource=resource,
        issued_by=issued_by,
    )
    _append_audit_event(
        "agent_approval_issued",
        {
            "id": rec.get("id"),
            "action": rec.get("action"),
            "resource": rec.get("resource"),
            "expires_at_utc": rec.get("expires_at_utc"),
            "uses_remaining": rec.get("uses_remaining"),
        },
    )
    typer.echo(json.dumps({"status": "ok", "approval": rec}, indent=2, sort_keys=True))


@app.command("approval-list")
def agent_approval_list(
    show_revoked: bool = typer.Option(False, "--show-revoked")
) -> None:
    """List approval grants without exposing secret material."""
    approvals = list_approvals(include_revoked=show_revoked)
    typer.echo(
        json.dumps(
            {"status": "ok", "approvals": approvals},
            indent=2,
            sort_keys=True,
        )
    )


@app.command("approval-revoke")
def agent_approval_revoke(
    approval_id: str = typer.Argument(..., help="Approval id to revoke")
) -> None:
    """Revoke an approval grant by id."""
    if not revoke_approval(approval_id):
        typer.echo(
            json.dumps({"status": "error", "reason": "approval_not_found"}, indent=2)
        )
        raise typer.Exit(1)
    _append_audit_event("agent_approval_revoked", {"id": approval_id})
    typer.echo(json.dumps({"status": "ok", "approval_id": approval_id}, indent=2))


@app.command("lease-consume")
def agent_lease_consume(
    ctx: typer.Context,
    lease_id: str = typer.Argument(..., help="Secret lease id"),
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
        help="Keyring account (defaults to lease fingerprint)",
    ),
    broker_command: Optional[str] = typer.Option(
        None,
        "--broker-command",
        help="Command that prints password to stdout for --auth-broker=command",
    ),
    reveal: bool = typer.Option(
        False,
        "--reveal",
        help="Return plaintext secret instead of redacted output",
    ),
) -> None:
    """Consume one use from a secret lease and return the secret."""
    requested_fp = (ctx.obj or {}).get("fingerprint")
    ok, reason, lease = consume_lease(
        lease_id=lease_id, fingerprint=str(requested_fp) if requested_fp else None
    )
    if not ok or lease is None:
        payload = {"status": "denied", "reason": reason, "lease_id": lease_id}
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        raise typer.Exit(1)

    fingerprint = str(lease.get("fingerprint", ""))
    if not fingerprint:
        payload = {
            "status": "error",
            "reason": "lease_missing_fingerprint",
            "lease_id": lease_id,
        }
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        raise typer.Exit(1)
    if requested_fp and str(requested_fp) != fingerprint:
        payload = {
            "status": "denied",
            "reason": "lease_fingerprint_mismatch",
            "lease_id": lease_id,
            "fingerprint": fingerprint,
        }
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        raise typer.Exit(1)

    password = _agent_password(
        broker=auth_broker,
        password_env=password_env,
        broker_service=broker_service,
        broker_account=broker_account or fingerprint,
        broker_command=broker_command,
    )

    pm = PasswordManager(fingerprint=fingerprint, password=password)
    service = EntryService(pm)
    index = int(lease.get("index", -1))
    entry = service.retrieve_entry(index)
    if not isinstance(entry, dict):
        payload = {"status": "error", "reason": "entry_not_found", "lease_id": lease_id}
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        raise typer.Exit(1)
    kind = str(entry.get("type", entry.get("kind", "")))
    label = str(entry.get("label", ""))
    if kind != str(lease.get("kind", "")):
        payload = {
            "status": "denied",
            "reason": "lease_resource_mismatch",
            "lease_id": lease_id,
            "lease_kind": lease.get("kind"),
            "entry_kind": kind,
        }
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        raise typer.Exit(1)

    try:
        policy = _load_policy(strict=True)
        policy = _normalize_policy(policy, strict=False)
    except ValueError as exc:
        payload = {"status": "denied", "reason": "invalid_policy", "detail": str(exc)}
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        raise typer.Exit(1)

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
            "lease_id": lease_id,
            "fingerprint": fingerprint,
            "index": index,
            "kind": kind,
            "label": label,
        }
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        raise typer.Exit(1)

    if _high_risk_lock_required(policy, kind):
        unlocked, _expires_at = high_risk_unlocked(fingerprint=str(fingerprint))
        if not unlocked:
            payload = {
                "status": "denied",
                "reason": "policy_deny:high_risk_locked",
                "lease_id": lease_id,
                "fingerprint": fingerprint,
                "index": index,
                "kind": kind,
                "label": label,
            }
            typer.echo(json.dumps(payload, indent=2, sort_keys=True))
            raise typer.Exit(1)

    if kind in PRIVATE_KINDS:
        try:
            entry = _hydrate_partition_entry_if_needed(
                pm, fingerprint=str(fingerprint), index=int(index), entry=entry
            )
        except ValueError as exc:
            payload = {
                "status": "denied",
                "reason": str(exc),
                "lease_id": lease_id,
                "fingerprint": fingerprint,
                "index": index,
                "kind": kind,
                "label": label,
            }
            typer.echo(json.dumps(payload, indent=2, sort_keys=True))
            raise typer.Exit(1)
        kind = str(entry.get("type", entry.get("kind", kind)))
        label = str(entry.get("label", label))

    try:
        secret = _resolve_secret_for_kind(pm, service, entry, index)
    except ValueError as exc:
        payload = {"status": "error", "reason": str(exc), "kind": kind}
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        raise typer.Exit(1)

    safe_default = bool(policy.get("output", {}).get("safe_output_default", True))
    redacted = safe_default and not reveal
    output_secret = _mask_secret(secret) if redacted else secret
    payload = {
        "status": "ok",
        "lease_id": lease_id,
        "fingerprint": fingerprint,
        "index": index,
        "kind": kind,
        "label": label,
        "safe_output": redacted,
        "secret": output_secret,
        "lease_uses_remaining": int(lease.get("uses_remaining", 0)),
        "policy_decision": decision,
    }
    _append_audit_event(
        "agent_secret_lease_consumed",
        {
            "lease_id": lease_id,
            "fingerprint": fingerprint,
            "index": index,
            "kind": kind,
            "label": label,
            "safe_output": redacted,
            "uses_remaining": int(lease.get("uses_remaining", 0)),
        },
    )
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


@app.command("lease-list")
def agent_lease_list(
    show_revoked: bool = typer.Option(False, "--show-revoked")
) -> None:
    """List secret lease records."""
    leases = list_leases(include_revoked=show_revoked)
    typer.echo(json.dumps({"status": "ok", "leases": leases}, indent=2, sort_keys=True))


@app.command("lease-revoke")
def agent_lease_revoke(
    lease_id: str = typer.Argument(..., help="Lease id to revoke")
) -> None:
    """Revoke a secret lease."""
    if not revoke_lease(lease_id):
        payload = {"status": "error", "reason": "lease_not_found", "lease_id": lease_id}
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        raise typer.Exit(1)
    _append_audit_event("agent_secret_lease_revoked", {"lease_id": lease_id})
    typer.echo(
        json.dumps({"status": "ok", "lease_id": lease_id}, indent=2, sort_keys=True)
    )


@app.command("job-run")
def agent_job_run(
    ctx: typer.Context,
    query: str = typer.Argument(..., help="Entry label or index query"),
    password_env: str = typer.Option(
        "SEEDPASS_PASSWORD", "--password-env", help="Env var containing master password"
    ),
    auth_broker: str = typer.Option(
        "keyring",
        "--auth-broker",
        help="Job-safe password broker (keyring|command|env)",
        click_type=click.Choice(["keyring", "command", "env"], case_sensitive=False),
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
    reveal: bool = typer.Option(
        False,
        "--reveal",
        help="Return plaintext secret instead of redacted output",
    ),
    lease_only: bool = typer.Option(
        False,
        "--lease-only",
        help="Issue a secret lease instead of returning the secret directly",
    ),
    lease_ttl: int = typer.Option(
        30,
        "--lease-ttl",
        min=1,
        help="Lease TTL in seconds when --lease-only is used",
    ),
    lease_uses: int = typer.Option(
        1,
        "--lease-uses",
        min=1,
        help="Allowed successful retrievals for issued lease",
    ),
    allow_env_broker: bool = typer.Option(
        False,
        "--allow-env-broker",
        help="Allow env broker for jobs (less safe; disabled by default)",
    ),
    approval_id: Optional[str] = typer.Option(
        None,
        "--approval-id",
        help="Approval id for risky retrieval actions",
    ),
) -> None:
    """Run a scheduled-safe secret retrieval using brokered auth defaults."""
    broker = str(auth_broker).strip().lower()
    if broker == "env" and not allow_env_broker:
        payload = {
            "status": "denied",
            "reason": "unsafe_broker_for_job",
            "allowed_brokers": sorted(SAFE_AUTOMATION_BROKERS),
        }
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        raise typer.Exit(1)

    ctx.invoke(
        agent_get,
        query=query,
        password_env=password_env,
        auth_broker=broker,
        broker_service=broker_service,
        broker_account=broker_account,
        broker_command=broker_command,
        token=token,
        ttl=lease_ttl,
        lease_only=lease_only,
        lease_uses=lease_uses,
        reveal=reveal,
        approval_id=approval_id,
    )


@app.command("job-template")
def agent_job_template(
    ctx: typer.Context,
    query: str = typer.Argument(..., help="Entry label or index query"),
    mode: str = typer.Option(
        "cron",
        "--mode",
        help="Automation template format",
        click_type=click.Choice(["cron", "systemd"], case_sensitive=False),
    ),
    auth_broker: str = typer.Option(
        "keyring",
        "--auth-broker",
        help="Recommended broker for automated jobs",
        click_type=click.Choice(["keyring", "command"], case_sensitive=False),
    ),
    broker_service: str = typer.Option(
        "seedpass",
        "--broker-service",
        help="Keyring service when --auth-broker=keyring",
    ),
    broker_account: Optional[str] = typer.Option(
        None,
        "--broker-account",
        help="Broker account (defaults to fingerprint)",
    ),
    schedule: str = typer.Option(
        "*/15 * * * *",
        "--schedule",
        help="Cron expression or systemd OnCalendar value",
    ),
    unit_name: str = typer.Option(
        "seedpass-agent-job",
        "--unit-name",
        help="Systemd unit base name for --mode systemd",
    ),
    reveal: bool = typer.Option(False, "--reveal"),
    lease_only: bool = typer.Option(False, "--lease-only"),
    lease_ttl: int = typer.Option(30, "--lease-ttl", min=1),
    lease_uses: int = typer.Option(1, "--lease-uses", min=1),
    format: str = typer.Option(
        "json",
        "--format",
        help="Output format",
        click_type=click.Choice(["json", "text"], case_sensitive=False),
    ),
) -> None:
    """Generate deterministic cron/systemd templates using safer auth defaults."""
    fingerprint = (ctx.obj or {}).get("fingerprint")
    if not fingerprint:
        raise typer.BadParameter("Specify target profile with --fingerprint.")
    broker_account_value = broker_account or str(fingerprint)
    cmd = _automation_job_command(
        fingerprint=str(fingerprint),
        query=query,
        auth_broker=str(auth_broker).strip().lower(),
        broker_service=broker_service,
        broker_account=broker_account_value,
        reveal=reveal,
        lease_only=lease_only,
        lease_ttl=lease_ttl,
        lease_uses=lease_uses,
    )

    mode_value = str(mode).strip().lower()
    payload: dict[str, Any] = {
        "status": "ok",
        "mode": mode_value,
        "fingerprint": str(fingerprint),
        "query": query,
        "auth_broker": str(auth_broker).strip().lower(),
        "broker_service": broker_service,
        "broker_account": broker_account_value,
        "command": cmd,
        "safe_defaults": {
            "requires_non_env_broker": True,
            "safe_output_default": True,
            "no_plaintext_password_env_required": True,
        },
    }
    if mode_value == "cron":
        payload["cron_line"] = _cron_template(schedule=schedule, command=cmd)
    else:
        service, timer = _systemd_templates(
            unit_name=unit_name, schedule=schedule, command=cmd
        )
        payload["systemd_service"] = service
        payload["systemd_timer"] = timer
        payload["unit_name"] = unit_name

    if str(format).strip().lower() == "json":
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        return

    lines = [
        f"Agent Job Template ({mode_value})",
        f"fingerprint: {fingerprint}",
        f"query: {query}",
        f"broker: {auth_broker}",
        "",
    ]
    if mode_value == "cron":
        lines.append(str(payload["cron_line"]))
    else:
        lines.extend(
            [
                "# service",
                str(payload["systemd_service"]),
                "",
                "# timer",
                str(payload["systemd_timer"]),
            ]
        )
    typer.echo("\n".join(lines))


@app.command("job-profile-create")
def agent_job_profile_create(
    ctx: typer.Context,
    job_id: str = typer.Option(..., "--id", help="Stable job profile id"),
    query: str = typer.Option(..., "--query", help="Entry label or index query"),
    auth_broker: str = typer.Option(
        "keyring",
        "--auth-broker",
        help="Broker for scheduled job retrieval (keyring|command)",
        click_type=click.Choice(["keyring", "command"], case_sensitive=False),
    ),
    broker_service: str = typer.Option(
        "seedpass",
        "--broker-service",
        help="Keyring service name when --auth-broker=keyring",
    ),
    broker_account: Optional[str] = typer.Option(
        None,
        "--broker-account",
        help="Broker account (defaults to fingerprint)",
    ),
    broker_command: Optional[str] = typer.Option(
        None,
        "--broker-command",
        help="Command that prints password to stdout for --auth-broker=command",
    ),
    policy_binding: str = typer.Option(
        "default",
        "--policy-binding",
        help="Policy binding label for governance/audit metadata",
    ),
    bind_host: str = typer.Option(
        "current",
        "--bind-host",
        help="Host binding for this job profile (`current` or explicit hostname)",
    ),
    schedule: str = typer.Option(
        "",
        "--schedule",
        help="Optional schedule hint (cron or OnCalendar) stored as metadata",
    ),
    description: str = typer.Option(
        "",
        "--description",
        help="Optional operator-facing description",
    ),
    lease_only: bool = typer.Option(False, "--lease-only"),
    lease_ttl: int = typer.Option(30, "--lease-ttl", min=1),
    lease_uses: int = typer.Option(1, "--lease-uses", min=1),
    reveal: bool = typer.Option(False, "--reveal"),
) -> None:
    """Create a reusable automation job profile with safe broker defaults."""
    fingerprint = (ctx.obj or {}).get("fingerprint")
    if not fingerprint:
        raise typer.BadParameter("Specify target profile with --fingerprint.")
    broker = str(auth_broker).strip().lower()
    if broker == "command" and not str(broker_command or "").strip():
        raise typer.BadParameter(
            "--broker-command is required for --auth-broker=command"
        )
    account = str(broker_account or fingerprint)
    policy = _load_policy(strict=False)
    policy_stamp = compute_policy_stamp(policy)
    bind_host_value = str(bind_host).strip() or "current"
    if bind_host_value == "current":
        bind_host_value = socket.gethostname()
    try:
        rec = create_job_profile(
            job_id=job_id,
            fingerprint=str(fingerprint),
            query=query,
            auth_broker=broker,
            broker_service=broker_service,
            broker_account=account,
            broker_command=broker_command,
            policy_binding=policy_binding,
            policy_stamp=policy_stamp,
            schedule=schedule,
            description=description,
            host_binding=bind_host_value,
            lease_only=lease_only,
            lease_ttl=lease_ttl,
            lease_uses=lease_uses,
            reveal=reveal,
        )
    except ValueError as exc:
        payload = {"status": "error", "reason": str(exc), "id": job_id}
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        raise typer.Exit(1)
    _append_audit_event(
        "agent_job_profile_created",
        {
            "id": rec.get("id"),
            "fingerprint": rec.get("fingerprint"),
            "auth_broker": rec.get("auth_broker"),
            "policy_binding": rec.get("policy_binding"),
            "policy_stamp": rec.get("policy_stamp"),
            "host_binding": rec.get("host_binding"),
        },
    )
    typer.echo(
        json.dumps({"status": "ok", "job_profile": rec}, indent=2, sort_keys=True)
    )


@app.command("job-profile-list")
def agent_job_profile_list(
    show_revoked: bool = typer.Option(False, "--show-revoked")
) -> None:
    """List automation job profiles."""
    jobs = list_job_profiles(include_revoked=show_revoked)
    typer.echo(
        json.dumps({"status": "ok", "job_profiles": jobs}, indent=2, sort_keys=True)
    )


@app.command("job-profile-revoke")
def agent_job_profile_revoke(
    job_id: str = typer.Argument(..., help="Job profile id")
) -> None:
    """Revoke a stored automation job profile."""
    if not revoke_job_profile(job_id):
        payload = {"status": "error", "reason": "job_profile_not_found", "id": job_id}
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        raise typer.Exit(1)
    _append_audit_event("agent_job_profile_revoked", {"id": job_id})
    typer.echo(json.dumps({"status": "ok", "id": job_id}, indent=2, sort_keys=True))


@app.command("job-profile-run")
def agent_job_profile_run(
    ctx: typer.Context,
    job_id: str = typer.Argument(..., help="Job profile id"),
    password_env: str = typer.Option(
        "SEEDPASS_PASSWORD", "--password-env", help="Env var containing master password"
    ),
    token: Optional[str] = typer.Option(
        None,
        "--token",
        help="Scoped agent token. Defaults to SEEDPASS_AGENT_TOKEN env var.",
    ),
    approval_id: Optional[str] = typer.Option(
        None,
        "--approval-id",
        help="Approval id for risky retrieval actions",
    ),
    allow_policy_drift: bool = typer.Option(
        False,
        "--allow-policy-drift",
        help="Allow run when active policy stamp differs from profile policy stamp",
    ),
    allow_host_mismatch: bool = typer.Option(
        False,
        "--allow-host-mismatch",
        help="Allow run when current host differs from profile host binding",
    ),
) -> None:
    """Run an automation job profile with stored non-interactive settings."""
    profile = get_job_profile(job_id)
    if not profile or profile.get("revoked_at_utc"):
        payload = {"status": "error", "reason": "job_profile_not_found", "id": job_id}
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        raise typer.Exit(1)
    requested_fp = (ctx.obj or {}).get("fingerprint")
    profile_fp = str(profile.get("fingerprint", "")).strip()
    if requested_fp and str(requested_fp) != profile_fp:
        payload = {
            "status": "denied",
            "reason": "job_profile_fingerprint_mismatch",
            "id": job_id,
            "job_fingerprint": profile_fp,
            "requested_fingerprint": str(requested_fp),
        }
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        raise typer.Exit(1)
    bound_host = str(profile.get("host_binding", "")).strip()
    current_host = socket.gethostname()
    if bound_host and bound_host != current_host and not allow_host_mismatch:
        payload = {
            "status": "denied",
            "reason": "job_profile_host_mismatch",
            "id": job_id,
            "job_host": bound_host,
            "current_host": current_host,
        }
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        raise typer.Exit(1)
    profile_stamp = str(profile.get("policy_stamp", "")).strip()
    if profile_stamp:
        active_policy = _load_policy(strict=False)
        active_stamp = compute_policy_stamp(active_policy)
        if active_stamp != profile_stamp and not allow_policy_drift:
            payload = {
                "status": "denied",
                "reason": "job_profile_policy_mismatch",
                "id": job_id,
                "job_policy_stamp": profile_stamp,
                "active_policy_stamp": active_stamp,
            }
            typer.echo(json.dumps(payload, indent=2, sort_keys=True))
            raise typer.Exit(1)
    ctx.invoke(
        agent_job_run,
        query=str(profile.get("query", "")),
        password_env=password_env,
        auth_broker=str(profile.get("auth_broker", "keyring")),
        broker_service=str(profile.get("broker_service", "seedpass")),
        broker_account=str(profile.get("broker_account", profile_fp)),
        broker_command=str(profile.get("broker_command", "") or None),
        token=token,
        reveal=bool(profile.get("reveal", False)),
        lease_only=bool(profile.get("lease_only", False)),
        lease_ttl=int(profile.get("lease_ttl", 30)),
        lease_uses=int(profile.get("lease_uses", 1)),
        allow_env_broker=False,
        approval_id=approval_id,
    )


@app.command("job-profile-check")
def agent_job_profile_check(
    max_age_days: int = typer.Option(
        30,
        "--max-age-days",
        min=1,
        help="Flag job profiles older than this age",
    ),
    strict_exit: bool = typer.Option(
        False,
        "--strict-exit/--no-strict-exit",
        help="Return non-zero exit when findings are present",
    ),
) -> None:
    """Check job profile posture (policy drift, host mismatch, stale configs)."""
    jobs = list_job_profiles(include_revoked=False)
    active_policy = _load_policy(strict=False)
    active_stamp = compute_policy_stamp(active_policy)
    now = _utcnow()
    findings: list[dict[str, Any]] = []
    for rec in jobs:
        job_id = str(rec.get("id", ""))
        broker = str(rec.get("auth_broker", "")).strip().lower()
        if broker not in SAFE_AUTOMATION_BROKERS:
            findings.append(
                {
                    "id": "job_profile_unsafe_broker",
                    "severity": "high",
                    "job_id": job_id,
                    "broker": broker,
                    "message": "Job profile uses unsafe broker mode.",
                }
            )
        profile_stamp = str(rec.get("policy_stamp", "")).strip()
        if profile_stamp and profile_stamp != active_stamp:
            findings.append(
                {
                    "id": "job_profile_policy_mismatch",
                    "severity": "medium",
                    "job_id": job_id,
                    "job_policy_stamp": profile_stamp,
                    "active_policy_stamp": active_stamp,
                    "message": "Job profile policy stamp differs from active policy.",
                }
            )
        bound_host = str(rec.get("host_binding", "")).strip()
        current_host = socket.gethostname()
        if bound_host and bound_host != current_host:
            findings.append(
                {
                    "id": "job_profile_host_mismatch",
                    "severity": "medium",
                    "job_id": job_id,
                    "job_host": bound_host,
                    "current_host": current_host,
                    "message": "Job profile host binding does not match current host.",
                }
            )
        created_at = str(rec.get("created_at_utc", ""))
        if created_at:
            try:
                age_days = (_utcnow() - _parse_iso8601(created_at)).days
                if age_days > max_age_days:
                    findings.append(
                        {
                            "id": "job_profile_stale",
                            "severity": "low",
                            "job_id": job_id,
                            "age_days": age_days,
                            "message": "Job profile has exceeded recommended age.",
                        }
                    )
            except Exception:
                pass
    payload = {
        "status": "ok",
        "check": "agent_job_profiles",
        "job_profile_count": len(jobs),
        "active_policy_stamp": active_stamp,
        "finding_count": len(findings),
        "findings": findings,
        "generated_at_utc": now.isoformat(),
    }
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    if strict_exit and findings:
        raise typer.Exit(1)


@app.command("recovery-split")
def agent_recovery_split(
    secret: Optional[str] = typer.Option(
        None,
        "--secret",
        help="Secret material to split (avoid shell history for sensitive values)",
    ),
    secret_env: str = typer.Option(
        "SEEDPASS_RECOVERY_SECRET",
        "--secret-env",
        help="Environment variable containing secret material",
    ),
    shares: int = typer.Option(5, "--shares", min=2, help="Total number of shares"),
    threshold: int = typer.Option(
        3, "--threshold", min=2, help="Minimum shares required for recovery"
    ),
    label: str = typer.Option(
        "default", "--label", help="Recovery set label encoded in share tokens"
    ),
) -> None:
    """Split secret material into deterministic Shamir shares."""
    secret_value = str(secret or os.getenv(secret_env, "")).strip()
    if not secret_value:
        raise typer.BadParameter(
            "Provide --secret or set the environment variable from --secret-env."
        )
    try:
        tokens = split_secret(
            secret_value,
            total_shares=int(shares),
            threshold=int(threshold),
            label=label,
        )
    except ValueError as exc:
        payload = {"status": "error", "reason": str(exc)}
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        raise typer.Exit(1)
    payload = {
        "status": "ok",
        "label": str(label).strip() or "default",
        "threshold": int(threshold),
        "total_shares": int(shares),
        "shares": tokens,
    }
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


@app.command("recovery-recover")
def agent_recovery_recover(
    share: list[str] = typer.Option(
        None, "--share", help="Recovery share token (repeatable)"
    ),
    share_file: Optional[Path] = typer.Option(
        None, "--share-file", help="File with one share token per line"
    ),
    reveal: bool = typer.Option(
        False, "--reveal", help="Emit recovered secret plaintext"
    ),
) -> None:
    """Recover secret material from Shamir share tokens."""
    tokens = [str(v).strip() for v in (share or []) if str(v).strip()]
    if share_file:
        for line in share_file.read_text(encoding="utf-8").splitlines():
            value = line.strip()
            if value:
                tokens.append(value)
    if not tokens:
        raise typer.BadParameter("Provide at least one --share or --share-file input.")
    try:
        recovered = recover_secret(tokens)
    except ValueError as exc:
        payload = {"status": "error", "reason": str(exc)}
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        raise typer.Exit(1)
    payload = {
        "status": "ok",
        "share_count": len(tokens),
        "secret": recovered if reveal else _mask_secret(recovered),
        "revealed": bool(reveal),
    }
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


@app.command("recovery-drill")
def agent_recovery_drill(
    ctx: typer.Context,
    backup_path: Path = typer.Option(
        ..., "--backup-path", help="Path to backup file to validate"
    ),
    simulated: bool = typer.Option(
        True, "--simulated/--no-simulated", help="Mark drill as simulated run"
    ),
    max_age_days: Optional[int] = typer.Option(
        30,
        "--max-age-days",
        min=1,
        help="Warn when backup age exceeds this many days",
    ),
    strict_exit: bool = typer.Option(
        False,
        "--strict-exit/--no-strict-exit",
        help="Return non-zero exit when drill status is warning",
    ),
) -> None:
    """Run a signed backup verification drill and append report to recovery log."""
    fingerprint = (ctx.obj or {}).get("fingerprint") or "default"
    report = record_recovery_drill(
        fingerprint=str(fingerprint),
        backup_path=str(backup_path),
        simulated=bool(simulated),
        expected_max_age_days=max_age_days,
    )
    typer.echo(json.dumps({"status": "ok", "report": report}, indent=2, sort_keys=True))
    if strict_exit and str(report.get("status", "")) != "ok":
        raise typer.Exit(1)


@app.command("recovery-drill-list")
def agent_recovery_drill_list(
    limit: int = typer.Option(20, "--limit", min=1, max=200)
) -> None:
    """List recent signed recovery drill records."""
    records = list_recovery_drills(limit=int(limit))
    typer.echo(
        json.dumps(
            {"status": "ok", "count": len(records), "drills": records},
            indent=2,
            sort_keys=True,
        )
    )


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
            "approvals_required_for": list(
                policy.get("approvals", {}).get("require_for", [])
            ),
            "secret_isolation": {
                "enabled": bool(
                    policy.get("secret_isolation", {}).get("enabled", True)
                ),
                "high_risk_kinds": list(
                    policy.get("secret_isolation", {}).get("high_risk_kinds", [])
                ),
                "unlock_ttl_sec": int(
                    policy.get("secret_isolation", {}).get("unlock_ttl_sec", 300)
                ),
            },
        },
        "tokens": _token_posture_summary(),
        "identities": {
            "total": len(list_identities(include_revoked=True)),
            "active": len(list_identities(include_revoked=False)),
        },
        "auth_brokers": {
            "supported": ["env", "keyring", "command"],
            "default_agent_get": "env",
            "default_agent_init": "env",
        },
        "commands": {
            "policy": [
                "agent policy-show",
                "agent policy-lint",
                "agent policy-set",
                "agent policy-review",
                "agent policy-apply",
            ],
            "identities": [
                "agent identity-create",
                "agent identity-list",
                "agent identity-revoke",
            ],
            "tokens": ["agent token-issue", "agent token-list", "agent token-revoke"],
            "approvals": [
                "agent approval-issue",
                "agent approval-list",
                "agent approval-revoke",
            ],
            "leases": [
                "agent get --lease-only",
                "agent lease-consume",
                "agent lease-list",
                "agent lease-revoke",
            ],
            "automation": [
                "agent job-run",
                "agent job-template",
                "agent job-profile-create",
                "agent job-profile-list",
                "agent job-profile-run",
                "agent job-profile-revoke",
                "agent job-profile-check",
            ],
            "recovery": [
                "agent recovery-split",
                "agent recovery-recover",
                "agent recovery-drill",
                "agent recovery-drill-list",
            ],
            "secret_isolation": [
                "agent high-risk-factor-set",
                "agent high-risk-unlock",
                "agent high-risk-status",
                "agent high-risk-lock",
            ],
            "export_controls": [
                "agent export-check",
                "agent export-manifest-verify",
            ],
            "posture": ["agent posture-check", "agent posture-remediate"],
            "secret_access": ["agent get --fingerprint <fp> <query>"],
            "discovery": ["seedpass capabilities --format json", "seedpass --help"],
        },
    }
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


@app.command("posture-check")
def agent_posture_check(
    ctx: typer.Context,
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
    check_runtime_config: bool = typer.Option(
        False,
        "--check-runtime-config",
        help="Attempt profile runtime config checks (requires fingerprint + broker auth)",
    ),
    auth_broker: str = typer.Option(
        "env",
        "--auth-broker",
        help="Password broker for --check-runtime-config (env|keyring|command)",
        click_type=click.Choice(["env", "keyring", "command"], case_sensitive=False),
    ),
    password_env: str = typer.Option(
        "SEEDPASS_PASSWORD",
        "--password-env",
        help="Env var containing master password when --auth-broker=env",
    ),
    broker_service: str = typer.Option(
        "seedpass",
        "--broker-service",
        help="Keyring service name when --auth-broker=keyring",
    ),
    broker_account: Optional[str] = typer.Option(
        None,
        "--broker-account",
        help="Keyring account (defaults to active fingerprint)",
    ),
    broker_command: Optional[str] = typer.Option(
        None,
        "--broker-command",
        help="Command that prints password to stdout for --auth-broker=command",
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
    runtime_status = "not_requested"
    runtime_error = None
    runtime_finding_count = 0
    if check_runtime_config:
        fingerprint = str((ctx.obj or {}).get("fingerprint") or "").strip()
        if not fingerprint:
            payload = {
                "status": "error",
                "reason": "missing_fingerprint_for_runtime_check",
                "detail": "Provide --fingerprint when using --check-runtime-config.",
            }
            typer.echo(json.dumps(payload, indent=2, sort_keys=True))
            raise typer.Exit(1)
        try:
            password = _agent_password(
                broker=auth_broker,
                password_env=password_env,
                broker_service=broker_service,
                broker_account=broker_account or fingerprint,
                broker_command=broker_command,
            )
            pm = PasswordManager(fingerprint=fingerprint, password=password)
            runtime_findings = _runtime_config_findings(pm)
            findings.extend(runtime_findings)
            runtime_finding_count = len(runtime_findings)
            runtime_status = "checked"
        except Exception as exc:
            runtime_status = "error"
            runtime_error = str(exc)

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
        "runtime_config_status": runtime_status,
        "runtime_config_error": runtime_error,
        "runtime_finding_count": runtime_finding_count,
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


@app.command("posture-remediate")
def agent_posture_remediate(
    ctx: typer.Context,
    fail_on: str = typer.Option(
        "critical",
        "--fail-on",
        help="Minimum severity that marks bundle as blocked",
        click_type=click.Choice(
            ["info", "low", "medium", "high", "critical"], case_sensitive=False
        ),
    ),
    check_runtime_config: bool = typer.Option(
        False,
        "--check-runtime-config",
        help="Include runtime profile config checks (requires fingerprint + broker auth)",
    ),
    auth_broker: str = typer.Option(
        "env",
        "--auth-broker",
        help="Password broker for --check-runtime-config (env|keyring|command)",
        click_type=click.Choice(["env", "keyring", "command"], case_sensitive=False),
    ),
    password_env: str = typer.Option(
        "SEEDPASS_PASSWORD",
        "--password-env",
        help="Env var containing master password when --auth-broker=env",
    ),
    broker_service: str = typer.Option(
        "seedpass",
        "--broker-service",
        help="Keyring service name when --auth-broker=keyring",
    ),
    broker_account: Optional[str] = typer.Option(
        None,
        "--broker-account",
        help="Keyring account (defaults to active fingerprint)",
    ),
    broker_command: Optional[str] = typer.Option(
        None,
        "--broker-command",
        help="Command that prints password to stdout for --auth-broker=command",
    ),
) -> None:
    """Generate actionable remediation steps from current posture findings."""
    try:
        policy = _load_policy(strict=True)
        policy = _normalize_policy(policy, strict=False)
        policy_status = "ok"
    except ValueError:
        policy = _deny_all_policy()
        policy_status = "invalid"

    findings = _posture_findings(policy, policy_status)
    runtime_status = "not_requested"
    runtime_error = None
    if check_runtime_config:
        fingerprint = str((ctx.obj or {}).get("fingerprint") or "").strip()
        if not fingerprint:
            payload = {
                "status": "error",
                "reason": "missing_fingerprint_for_runtime_check",
                "detail": "Provide --fingerprint when using --check-runtime-config.",
            }
            typer.echo(json.dumps(payload, indent=2, sort_keys=True))
            raise typer.Exit(1)
        try:
            password = _agent_password(
                broker=auth_broker,
                password_env=password_env,
                broker_service=broker_service,
                broker_account=broker_account or fingerprint,
                broker_command=broker_command,
            )
            pm = PasswordManager(fingerprint=fingerprint, password=password)
            findings.extend(_runtime_config_findings(pm))
            runtime_status = "checked"
        except Exception as exc:
            runtime_status = "error"
            runtime_error = str(exc)

    highest = "info"
    for finding in findings:
        if _severity_rank(str(finding.get("severity", "info"))) > _severity_rank(
            highest
        ):
            highest = str(finding.get("severity", "info"))
    actions = _remediation_actions(findings)
    payload = {
        "status": "ok",
        "check": "agent_posture_remediation",
        "policy_status": policy_status,
        "runtime_config_status": runtime_status,
        "runtime_config_error": runtime_error,
        "finding_count": len(findings),
        "highest_severity": highest,
        "fail_on": fail_on.lower(),
        "blocked": _severity_rank(highest) >= _severity_rank(fail_on.lower()),
        "findings": findings,
        "actions": actions,
    }
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    if payload["blocked"]:
        raise typer.Exit(1)


@app.command("export-check")
def agent_export_check(
    mode: str = typer.Option(
        "full",
        "--mode",
        help="Export check mode",
        click_type=click.Choice(["full", "filtered", "kind"], case_sensitive=False),
    ),
    kind: Optional[str] = typer.Option(
        None,
        "--kind",
        help="Entry kind for --mode kind",
        click_type=click.Choice(ALL_ENTRY_TYPES, case_sensitive=False),
    ),
    strict_exit: bool = typer.Option(
        False,
        "--strict-exit",
        help="Return non-zero exit code when export is denied",
    ),
) -> None:
    """Dry-run export policy decision without exporting secrets."""
    try:
        policy = _load_policy(strict=True)
        policy = _normalize_policy(policy, strict=False)
    except ValueError as exc:
        payload = {
            "status": "denied",
            "mode": mode.lower(),
            "allowed": False,
            "reason": "invalid_policy",
            "detail": str(exc),
        }
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        raise typer.Exit(code=1)

    mode_l = mode.lower()
    allowed = False
    reason = "policy_deny:unknown"
    detail = None
    checked_kind = None
    if mode_l == "full":
        allowed, reason = evaluate_full_export(policy)
    elif mode_l == "filtered":
        allowed = True
        reason = "policy_allow:filtered_export"
    else:
        if not kind:
            payload = {
                "status": "error",
                "mode": mode_l,
                "allowed": False,
                "reason": "missing_kind",
                "detail": "Provide --kind when --mode kind is used.",
            }
            typer.echo(json.dumps(payload, indent=2, sort_keys=True))
            raise typer.Exit(code=1)
        checked_kind = kind
        allowed, reason = evaluate_kind_export(policy, kind)

    payload = {
        "status": "ok",
        "mode": mode_l,
        "allowed": bool(allowed),
        "reason": reason,
        "kind": checked_kind,
        "allow_kinds": sorted(set(policy.get("allow_kinds", []))),
        "allow_export_import": bool(policy.get("allow_export_import", False)),
        "detail": detail,
    }
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    if strict_exit and not allowed:
        raise typer.Exit(code=1)


@app.command("export-manifest-verify")
def agent_export_manifest_verify(
    file: Path = typer.Option(
        ..., "--file", help="Path to policy-filtered export JSON"
    ),
    strict_exit: bool = typer.Option(
        True,
        "--strict-exit/--no-strict-exit",
        help="Return non-zero exit when verification fails",
    ),
) -> None:
    """Verify policy-filtered export manifest integrity against current policy."""
    try:
        package = json.loads(file.read_text(encoding="utf-8"))
    except Exception as exc:
        payload = {
            "status": "error",
            "valid": False,
            "reason": "invalid_json",
            "detail": str(exc),
            "file": str(file),
        }
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        raise typer.Exit(code=1)

    try:
        policy = _load_policy(strict=True)
        policy = _normalize_policy(policy, strict=False)
        policy_status = "ok"
    except ValueError as exc:
        policy = _deny_all_policy()
        policy_status = "invalid"
        policy_error = str(exc)
    else:
        policy_error = None

    valid, errors = verify_filtered_export_package(package, policy)
    payload = {
        "status": "ok",
        "valid": bool(valid),
        "file": str(file),
        "policy_status": policy_status,
        "policy_error": policy_error,
        "policy_stamp_current": compute_policy_stamp(policy),
        "policy_stamp_manifest": str(
            (package.get("_export_manifest") or {}).get("policy_stamp", "")
        ),
        "errors": errors,
    }
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    if strict_exit and not valid:
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
        help="Lease TTL in seconds when issuing secret leases",
    ),
    lease_only: bool = typer.Option(
        False,
        "--lease-only",
        help="Issue a secret lease without returning the secret directly",
    ),
    lease_uses: int = typer.Option(
        1,
        "--lease-uses",
        min=1,
        help="Allowed successful secret retrievals for issued lease",
    ),
    reveal: bool = typer.Option(
        False,
        "--reveal",
        help="Return plaintext secret instead of redacted output",
    ),
    approval_id: Optional[str] = typer.Option(
        None,
        "--approval-id",
        help="Approval id for risky retrieval actions",
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

    if _high_risk_lock_required(policy, kind):
        unlocked, expires_at = high_risk_unlocked(fingerprint=str(fingerprint))
        if not unlocked:
            payload = {
                "status": "denied",
                "reason": "policy_deny:high_risk_locked",
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
                    "reason": "policy_deny:high_risk_locked",
                },
            )
            typer.echo(json.dumps(payload, indent=2))
            raise typer.Exit(1)
    if kind in PRIVATE_KINDS:
        try:
            entry = _hydrate_partition_entry_if_needed(
                pm, fingerprint=str(fingerprint), index=int(index), entry=entry
            )
        except ValueError as exc:
            payload = {
                "status": "denied",
                "reason": str(exc),
                "kind": kind,
                "label": label,
                "index": index,
            }
            typer.echo(json.dumps(payload, indent=2))
            raise typer.Exit(1)
        kind = str(entry.get("type", entry.get("kind", kind)))
        label = str(entry.get("label", label))

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

    if kind in PRIVATE_KINDS and approval_required(policy, "private_key_retrieval"):
        if not approval_id:
            payload = {
                "status": "denied",
                "reason": "policy_deny:approval_required",
                "action": "private_key_retrieval",
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
                    "reason": "policy_deny:approval_required",
                    "action": "private_key_retrieval",
                },
            )
            typer.echo(json.dumps(payload, indent=2))
            raise typer.Exit(1)
        ok, approval_reason = consume_approval(
            approval_id=approval_id,
            action="private_key_retrieval",
            resource=f"entry:{kind}:{index}",
        )
        if not ok:
            reason = f"policy_deny:{approval_reason}"
            payload = {
                "status": "denied",
                "reason": reason,
                "action": "private_key_retrieval",
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
                    "reason": reason,
                    "action": "private_key_retrieval",
                    "approval_id": approval_id,
                },
            )
            typer.echo(json.dumps(payload, indent=2))
            raise typer.Exit(1)

    now = _utcnow()
    token_id = (token_meta or {}).get("id") if token_meta else None
    if lease_only:
        lease = issue_lease(
            fingerprint=str(fingerprint),
            index=index,
            kind=kind,
            label=label,
            ttl_seconds=ttl,
            uses=lease_uses,
            token_id=str(token_id) if token_id else None,
        )
        payload = {
            "status": "ok",
            "mode": "lease_issued",
            "fingerprint": fingerprint,
            "index": index,
            "kind": kind,
            "label": label,
            "lease_id": lease.get("id"),
            "lease_uses_remaining": int(lease.get("uses_remaining", 0)),
            "lease_expires_at_utc": lease.get("expires_at_utc"),
            "policy_decision": decision,
        }
        if token_meta is not None:
            payload["token_id"] = token_meta.get("id")
            payload["token_uses_remaining"] = token_meta.get("uses_remaining", 0)
        _append_audit_event(
            "agent_secret_lease_issued",
            {
                "lease_id": lease.get("id"),
                "fingerprint": fingerprint,
                "index": index,
                "kind": kind,
                "label": label,
                "uses_remaining": int(lease.get("uses_remaining", 0)),
                "expires_at_utc": lease.get("expires_at_utc"),
                "token_id": token_id,
            },
        )
        typer.echo(json.dumps(payload, indent=2))
        return

    try:
        secret = _resolve_secret_for_kind(pm, service, entry, index)
    except ValueError as exc:
        payload = {"status": "error", "reason": str(exc), "kind": kind}
        typer.echo(json.dumps(payload, indent=2))
        raise typer.Exit(1)

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
