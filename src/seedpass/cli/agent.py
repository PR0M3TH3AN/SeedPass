from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Optional

import bcrypt
import click
import typer
from bip_utils import Bip39Languages, Bip39MnemonicGenerator, Bip39WordsNum
from mnemonic import Mnemonic

from constants import APP_DIR, initialize_app
from seedpass.core.api import EntryService
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
    "allow_kinds": [
        EntryType.PASSWORD.value,
        EntryType.TOTP.value,
        EntryType.KEY_VALUE.value,
    ],
    "deny_private_reveal": sorted(PRIVATE_KINDS),
    "allow_export_import": False,
}


def _policy_path() -> Path:
    return APP_DIR / "agent_policy.json"


def _deny_all_policy() -> dict:
    return {
        "allow_kinds": [],
        "deny_private_reveal": list(ALL_ENTRY_TYPES),
        "allow_export_import": False,
    }


def _load_policy(*, strict: bool = False) -> dict:
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

    policy = dict(DEFAULT_POLICY)
    if isinstance(data.get("allow_kinds"), list):
        allow_kinds = [str(v) for v in data["allow_kinds"]]
        invalid = [v for v in allow_kinds if v not in ALL_ENTRY_TYPES]
        if invalid and strict:
            raise ValueError(f"agent policy has invalid allow_kinds entries: {invalid}")
        policy["allow_kinds"] = [v for v in allow_kinds if v in ALL_ENTRY_TYPES]
    if isinstance(data.get("deny_private_reveal"), list):
        deny_private = [str(v) for v in data["deny_private_reveal"]]
        invalid = [v for v in deny_private if v not in ALL_ENTRY_TYPES]
        if invalid and strict:
            raise ValueError(
                f"agent policy has invalid deny_private_reveal entries: {invalid}"
            )
        policy["deny_private_reveal"] = [
            v for v in deny_private if v in ALL_ENTRY_TYPES
        ]
    if isinstance(data.get("allow_export_import"), bool):
        policy["allow_export_import"] = data["allow_export_import"]
    return policy


def _save_policy(policy: dict) -> None:
    path = _policy_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(policy, indent=2), encoding="utf-8")
    os.chmod(path, 0o600)


def _password_from_env(var_name: str) -> str:
    value = os.getenv(var_name)
    if not value:
        raise typer.BadParameter(
            f"Missing password env var '{var_name}'. Export it before running this command."
        )
    return value


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
    switch_existing: bool = typer.Option(
        False,
        "--switch-existing",
        help="Switch to existing profile if the seed fingerprint already exists",
    ),
    kdf_iterations: int = typer.Option(
        100_000, "--kdf-iterations", help="PBKDF2 iterations for profile setup"
    ),
    print_seed: bool = typer.Option(
        False, "--print-seed", help="Include generated seed in JSON output"
    ),
) -> None:
    """Initialize a profile non-interactively for agent workflows."""
    initialize_app()
    password = _password_from_env(password_env)
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
) -> None:
    """Set policy flags used by agent commands."""
    policy = _load_policy(strict=False)
    if allow_kind:
        policy["allow_kinds"] = list(allow_kind)
    if deny_private_kind:
        policy["deny_private_reveal"] = list(deny_private_kind)
    policy["allow_export_import"] = bool(allow_export_import)
    _save_policy(policy)
    typer.echo(json.dumps(policy, indent=2))


@app.command("get")
def agent_get(
    ctx: typer.Context,
    query: str = typer.Argument(..., help="Entry label or index query"),
    password_env: str = typer.Option(
        "SEEDPASS_PASSWORD", "--password-env", help="Env var containing master password"
    ),
    ttl: int = typer.Option(
        30,
        "--ttl",
        min=1,
        help="Lease time in seconds for the returned secret metadata",
    ),
) -> None:
    """Retrieve one secret as JSON with policy enforcement."""
    fingerprint = (ctx.obj or {}).get("fingerprint")
    if not fingerprint:
        raise typer.BadParameter("Specify target profile with --fingerprint.")
    password = _password_from_env(password_env)
    try:
        policy = _load_policy(strict=True)
    except ValueError as exc:
        typer.echo(
            json.dumps(
                {
                    "status": "denied",
                    "reason": "invalid_policy",
                    "detail": str(exc),
                },
                indent=2,
            )
        )
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
        typer.echo(json.dumps(payload, indent=2))
        raise typer.Exit(1)

    index = matches[0][0]
    entry = service.retrieve_entry(index)
    kind = entry.get("type", entry.get("kind"))
    if kind is None:
        raise typer.BadParameter("Entry kind missing.")

    allow_kinds = set(policy.get("allow_kinds", []))
    deny_private = set(policy.get("deny_private_reveal", []))
    if allow_kinds and kind not in allow_kinds:
        typer.echo(
            json.dumps(
                {
                    "status": "denied",
                    "reason": "kind_not_allowed",
                    "kind": kind,
                    "policy": policy,
                },
                indent=2,
            )
        )
        raise typer.Exit(1)
    if kind in deny_private:
        typer.echo(
            json.dumps(
                {
                    "status": "denied",
                    "reason": "private_kind_blocked",
                    "kind": kind,
                    "policy": policy,
                },
                indent=2,
            )
        )
        raise typer.Exit(1)

    secret: Optional[str] = None
    if kind == EntryType.PASSWORD.value:
        secret = service.generate_password(int(entry.get("length", 12)), index)
    elif kind == EntryType.TOTP.value:
        secret = service.get_totp_code(index)
    elif kind == EntryType.KEY_VALUE.value:
        secret = entry.get("value")
    else:
        typer.echo(
            json.dumps(
                {
                    "status": "error",
                    "reason": "unsupported_kind_for_agent_get",
                    "kind": kind,
                },
                indent=2,
            )
        )
        raise typer.Exit(1)

    now = datetime.now(UTC)
    payload = {
        "status": "ok",
        "fingerprint": fingerprint,
        "index": index,
        "kind": kind,
        "label": entry.get("label"),
        "lease_ttl_sec": ttl,
        "issued_at_utc": now.isoformat(),
        "expires_at_utc": (now + timedelta(seconds=ttl)).isoformat(),
        "secret": secret,
    }
    typer.echo(json.dumps(payload, indent=2))
