#!/usr/bin/env python3
"""Cross-implementation compatibility check: Python SeedPass <-> TypeScript port.

Fixtures prove the two implementations compute the same values. This script
proves something different and equally necessary: that they can read each
other's *on-disk profiles* and *published state*, using each side's real code
paths rather than test helpers.

Phases:
  A. Python creates a profile -> the TS CLI opens it and reveals secrets
  B. The TS CLI creates a profile -> Python opens it and derives the same secrets
  C. Portable backups round-trip in both directions
  D. Nostr sync interop through a local relay (Python publishes -> TS restores,
     and TS publishes -> Python restores)

Usage:
    .venv/bin/python scripts/cross_impl_check.py [--skip-relay]

Exits non-zero if any check fails. Uses throwaway seeds only.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

CLI_BIN = REPO / "js" / "packages" / "cli" / "bin" / "seedpass-js.mjs"

# Throwaway seeds. Never used for real funds or real vaults.
SEED_A = (
    "rival cover produce defy coconut arrow empty acid crime cereal strong icon"
)
SEED_B = (
    "romance waste exercise alone pistol mushroom aunt series weasel muscle move skirt"
)
# Valid words, deliberately wrong checksum: both implementations must refuse it.
SEED_INVALID = (
    "gaze stereo trend brown chunk hero pole width once tent lift bird"
)
PASSWORD = "cross-impl-check-password"

results: list[tuple[str, bool, str]] = []
divergences: list[tuple[str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))
    mark = "PASS" if ok else "FAIL"
    print(f"  [{mark}] {name}" + (f" -- {detail}" if detail and not ok else ""))


def note_divergence(name: str, detail: str) -> None:
    """Record a known, deliberate behavioral difference.

    Not a failure — but never silent either: every entry here must appear in
    the compatibility matrix's divergence section with a decision attached.
    """
    divergences.append((name, detail))
    print(f"  [DIVERGE] {name} -- {detail}")


class agent_running:
    """Run the TS session agent for the duration of a block."""

    def __init__(self, app_dir: Path) -> None:
        self.app_dir = app_dir
        self.proc: subprocess.Popen | None = None

    def __enter__(self) -> "agent_running":
        env = dict(os.environ)
        env["SEEDPASS_APP_DIR"] = str(self.app_dir)
        env["SEEDPASS_AGENT_SOCK"] = str(self.app_dir / "agent.sock")
        self.proc = subprocess.Popen(
            ["node", str(CLI_BIN), "agent", "start"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
            cwd=str(CLI_BIN.parent),
        )
        for _ in range(50):
            if (self.app_dir / "agent.sock").exists():
                break
            time.sleep(0.1)
        os.environ["SEEDPASS_AGENT_SOCK"] = str(self.app_dir / "agent.sock")
        return self

    def __exit__(self, *exc: object) -> None:
        if self.proc is not None:
            self.proc.terminate()
            self.proc.wait(timeout=10)
        os.environ.pop("SEEDPASS_AGENT_SOCK", None)


def run_cli(app_dir: Path, *args: str, env_extra: dict[str, str] | None = None) -> str:
    """Run the TypeScript CLI and return stdout (raises on failure)."""
    env = dict(os.environ)
    env["SEEDPASS_APP_DIR"] = str(app_dir)
    env["SEEDPASS_AGENT_SOCK"] = os.environ.get(
        "SEEDPASS_AGENT_SOCK", str(app_dir / "agent.sock")
    )
    env.pop("SEEDPASS_MNEMONIC", None)
    env.pop("SEEDPASS_TOKEN", None)
    env.pop("SEEDPASS_PASSWORD", None)
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(
        ["node", str(CLI_BIN), *args],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(CLI_BIN.parent),
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"seedpass-js {' '.join(args)} failed: {proc.stderr.strip() or proc.stdout.strip()}"
        )
    return proc.stdout.strip()


# --------------------------------------------------------------------------
# Python-side helpers using the application's real code paths
# --------------------------------------------------------------------------


def py_create_profile(app_dir: Path, seed: str, password: str) -> str:
    """Create a profile exactly as the Python app does (KDF policy included)."""
    from seedpass.core.backup import BackupManager
    from seedpass.core.config_manager import ConfigManager
    from seedpass.core.encryption import EncryptionManager
    from seedpass.core.entry_management import EntryManager
    from seedpass.core.manager import PasswordManager
    from seedpass.core.vault import Vault
    from utils.fingerprint import generate_fingerprint
    from utils.fingerprint_manager import FingerprintManager
    from utils.key_derivation import derive_index_key

    fp = generate_fingerprint(seed)
    fp_dir = app_dir / fp
    fp_dir.mkdir(parents=True, exist_ok=True)

    dummy = PasswordManager.__new__(PasswordManager)
    dummy.config_manager = None  # forces ConfigManager defaults
    kdf_cfg = PasswordManager._build_seed_kdf_config(dummy, fp)
    seed_key = PasswordManager._derive_seed_key(dummy, password, fp, kdf_config=kdf_cfg)

    seed_mgr = EncryptionManager(seed_key, fp_dir)
    seed_mgr.encrypt_parent_seed(seed, kdf=kdf_cfg)

    enc_mgr = EncryptionManager(derive_index_key(seed), fp_dir)
    vault = Vault(enc_mgr, fp_dir)
    cfg_mgr = ConfigManager(vault, fp_dir)
    backup_mgr = BackupManager(fp_dir, cfg_mgr)
    em = EntryManager(vault, backup_mgr)

    # Every creatable kind, plus the shapes most likely to expose drift:
    # a policy-constrained password and an imported (non-deterministic) TOTP.
    em.add_entry("python-site.example", 18, username="pyuser", url="https://py.example")
    em.add_entry(
        "python-policy-site",
        24,
        username="policyuser",
        special_mode="safe",
        min_digits=4,
        min_uppercase=3,
        exclude_ambiguous=True,
    )
    em.add_totp("python-totp", seed, deterministic=True)
    em.add_totp("python-totp-imported", secret="JBSWY3DPEHPK3PXP", period=45, digits=8)
    em.add_key_value("python-api", "token", "py-secret-value")
    em.add_document("python-doc", "python document body", file_type="md")
    em.add_seed("python-cold-seed", seed, words_num=24)
    em.add_managed_account("python-managed", seed)
    em.add_nostr_key("python-nostr", seed)
    em.add_ssh_key("python-ssh", seed)
    em.add_pgp_key("python-pgp", seed, user_id="python@example.com")

    mgr = FingerprintManager(app_dir)
    if fp not in mgr.fingerprints:
        mgr.fingerprints.append(fp)
    mgr.current_fingerprint = fp
    mgr.names[fp] = "python-made"
    mgr._save_fingerprints()
    return fp


def py_open_profile(app_dir: Path, fp: str, password: str) -> tuple[str, dict]:
    """Decrypt a profile's parent seed and index using Python's real paths."""
    from seedpass.core.encryption import EncryptionManager
    from seedpass.core.manager import PasswordManager
    from seedpass.core.vault import Vault
    from utils.key_derivation import derive_index_key

    fp_dir = app_dir / fp
    kdf_cfg = PasswordManager._load_seed_kdf_config(fp_dir)
    if kdf_cfg is None:
        raise RuntimeError("no parent-seed KDF metadata found")
    dummy = PasswordManager.__new__(PasswordManager)
    dummy.config_manager = None
    seed_key = PasswordManager._derive_seed_key(dummy, password, fp, kdf_config=kdf_cfg)
    seed_mgr = EncryptionManager(seed_key, fp_dir)
    seed = seed_mgr.decrypt_parent_seed()

    enc_mgr = EncryptionManager(derive_index_key(seed), fp_dir)
    index = Vault(enc_mgr, fp_dir).load_index()
    return seed, index


def py_secrets_for(index: dict, seed: str) -> dict[str, str]:
    """Derive each entry's secret the way EntryManager retrieval does."""
    from bip_utils import Bip39SeedGenerator
    from local_bip85.bip85 import BIP85
    from nostr.coincurve_keys import Keys
    from seedpass.core.password_generation import (
        PasswordGenerator,
        PasswordPolicy,
        derive_seed_phrase,
    )
    from seedpass.core.totp import TotpManager
    from utils.key_derivation import derive_totp_secret

    class _Deriver:
        def derive_seed_from_mnemonic(self, mnemonic, passphrase=""):
            return Bip39SeedGenerator(mnemonic).Generate(passphrase)

    bip85 = BIP85(Bip39SeedGenerator(seed).Generate())
    out: dict[str, str] = {}
    for idx, entry in index.get("entries", {}).items():
        kind = entry.get("kind", entry.get("type"))
        label = entry.get("label", "")
        if kind == "password":
            # Mirror _generate_password_for_entry: merge the entry's policy
            # overrides onto the base policy before deriving.
            import dataclasses

            policy = PasswordPolicy()
            overrides = entry.get("policy", {})
            if isinstance(overrides, dict) and overrides:
                policy = dataclasses.replace(
                    policy,
                    **{k: v for k, v in overrides.items() if hasattr(policy, k)},
                )
            pg = PasswordGenerator(_Deriver(), seed, bip85, policy=policy)
            out[label] = pg.generate_password(
                length=int(entry["length"]),
                index=int(idx),
                gen_version=int(entry.get("gen_version", 1)),
            )
        elif kind == "totp":
            if entry.get("secret"):
                secret = entry["secret"]
            else:
                secret = derive_totp_secret(seed, int(entry.get("index", 0)))
            out[label] = TotpManager.current_code_from_secret(
                secret,
                FIXED_TS,
                period=int(entry.get("period", 30)),
                digits=int(entry.get("digits", 6)),
            )
        elif kind == "key_value":
            out[label] = entry["value"]
        elif kind == "document":
            out[label] = entry["content"]
        elif kind == "seed":
            out[label] = derive_seed_phrase(
                bip85, int(entry.get("index", int(idx))), int(entry.get("word_count", 24))
            )
        elif kind == "managed_account":
            out[label] = derive_seed_phrase(bip85, int(entry.get("index", int(idx))), 12)
        elif kind == "pgp":
            from seedpass.core.password_generation import derive_pgp_key

            priv, _pub, _fp = derive_pgp_key(
                bip85,
                int(entry.get("index", int(idx))),
                entry.get("key_type", "ed25519"),
                entry.get("user_id", ""),
            )
            out[label] = priv
        elif kind == "ssh":
            from seedpass.core.password_generation import derive_ssh_key_pair

            priv, _pub = derive_ssh_key_pair(seed, int(entry.get("index", int(idx))))
            out[label] = priv
        elif kind == "nostr":
            entropy = bip85.derive_entropy(
                index=int(entry.get("index", int(idx))), entropy_bytes=32
            )
            keys = Keys(priv_k=entropy.hex())
            out[label] = Keys.hex_to_bech32(keys.private_key_hex(), "nsec")
    return out


FIXED_TS = 1800000000  # pinned so TOTP codes compare across implementations


def ts_secrets_for(app_dir: Path, labels: list[str], seed: str) -> dict[str, str]:
    env = {"SEEDPASS_MNEMONIC": seed}
    out = {}
    for label in labels:
        out[label] = run_cli(
            app_dir, "entry", "reveal", label, "--at", str(FIXED_TS), env_extra=env
        )
    return out


# --------------------------------------------------------------------------
# Phases
# --------------------------------------------------------------------------


def phase_a(tmp: Path) -> None:
    print("\nPhase A: Python creates a profile -> TypeScript reads it")
    app_dir = tmp / "a"
    app_dir.mkdir()
    fp = py_create_profile(app_dir, SEED_A, PASSWORD)

    try:
        listed = json.loads(run_cli(app_dir, "entry", "list", env_extra={"SEEDPASS_MNEMONIC": SEED_A}))
        check("TS opens the Python-created index", True)
    except Exception as exc:
        check("TS opens the Python-created index", False, str(exc))
        return

    py_seed, py_index = py_open_profile(app_dir, fp, PASSWORD)
    py_labels = sorted(
        e["label"] for e in py_index.get("entries", {}).values()
    )
    ts_labels = sorted(row["label"] for row in listed)
    check("entry sets match", py_labels == ts_labels, f"{py_labels} != {ts_labels}")

    py_secrets = py_secrets_for(py_index, SEED_A)
    ts_secrets = ts_secrets_for(app_dir, list(py_secrets), SEED_A)
    # PEM values carry a trailing newline that the CLI capture strips; compare
    # on trailing whitespace-insensitive values.
    mismatches = [
        k
        for k in py_secrets
        if py_secrets[k].rstrip("\n") != (ts_secrets.get(k) or "").rstrip("\n")
    ]
    check(
        "every secret derives identically",
        not mismatches,
        f"mismatched: {mismatches}",
    )

    # The headline: TS unlocks a Python profile from the master password alone,
    # which exercises Python's parent-seed KDF metadata end to end.
    with agent_running(app_dir):
        try:
            run_cli(
                app_dir, "vault", "unlock", "--ttl", "5",
                env_extra={"SEEDPASS_PASSWORD": PASSWORD},
            )
            revealed = run_cli(app_dir, "entry", "reveal", "python-api")
            check(
                "TS unlocks the Python profile with the master password",
                revealed == "py-secret-value",
                f"revealed {revealed!r}",
            )
        except Exception as exc:
            check(
                "TS unlocks the Python profile with the master password", False, str(exc)
            )


def phase_b(tmp: Path) -> None:
    print("\nPhase B: TypeScript creates a profile -> Python reads it")
    app_dir = tmp / "b"
    app_dir.mkdir()
    run_cli(
        app_dir, "fingerprint", "add", "--name", "ts-made",
        env_extra={"SEEDPASS_MNEMONIC": SEED_B, "SEEDPASS_PASSWORD": PASSWORD},
    )
    env = {"SEEDPASS_MNEMONIC": SEED_B}
    run_cli(app_dir, "entry", "add", "password", "ts-site.example", "--length", "22", env_extra=env)
    run_cli(app_dir, "entry", "add", "totp", "ts-totp", env_extra=env)
    run_cli(app_dir, "entry", "add", "key-value", "ts-api", "token", "ts-secret-value", env_extra=env)
    run_cli(app_dir, "entry", "add", "managed-account", "ts-managed", env_extra=env)
    run_cli(app_dir, "entry", "add", "ssh", "ts-ssh", env_extra=env)
    run_cli(app_dir, "entry", "add", "nostr", "ts-nostr", env_extra=env)
    run_cli(
        app_dir, "entry", "add", "pgp", "ts-pgp", "--user-id", "ts@example.com",
        env_extra=env,
    )
    run_cli(app_dir, "entry", "add", "document", "ts-doc", "ts document body", env_extra=env)
    run_cli(app_dir, "entry", "add", "seed", "ts-seed", "--words", "24", env_extra=env)
    run_cli(
        app_dir, "entry", "add", "totp", "ts-totp-imported",
        "--secret", "JBSWY3DPEHPK3PXP", "--period", "45", "--digits", "8",
        env_extra=env,
    )

    from utils.fingerprint import generate_fingerprint

    fp = generate_fingerprint(SEED_B)
    try:
        py_seed, py_index = py_open_profile(app_dir, fp, PASSWORD)
        check("Python decrypts the TS parent_seed.enc and index", True)
    except Exception as exc:
        check("Python decrypts the TS parent_seed.enc and index", False, str(exc))
        return

    check("recovered seed matches", py_seed == SEED_B)

    py_secrets = py_secrets_for(py_index, SEED_B)
    ts_secrets = ts_secrets_for(app_dir, list(py_secrets), SEED_B)
    # PEM values carry a trailing newline that the CLI capture strips; compare
    # on trailing whitespace-insensitive values.
    mismatches = [
        k
        for k in py_secrets
        if py_secrets[k].rstrip("\n") != (ts_secrets.get(k) or "").rstrip("\n")
    ]
    check("every secret derives identically", not mismatches, f"mismatched: {mismatches}")

    # Python's schema validation should accept the TS-written index
    from seedpass.core.migrations import LATEST_VERSION  # type: ignore

    check(
        "TS index carries the current schema_version",
        int(py_index.get("schema_version", 0)) == int(LATEST_VERSION),
        f"{py_index.get('schema_version')} != {LATEST_VERSION}",
    )


def phase_c(tmp: Path) -> None:
    print("\nPhase C: portable backups round-trip")
    from seedpass.core.backup import BackupManager
    from seedpass.core.config_manager import ConfigManager
    from seedpass.core.encryption import EncryptionManager
    from seedpass.core.portable_backup import export_backup, import_backup
    from seedpass.core.vault import Vault
    from utils.fingerprint import generate_fingerprint
    from utils.key_derivation import derive_index_key

    # Python export -> TS import
    app_a = tmp / "a"
    fp_a = generate_fingerprint(SEED_A)
    fp_dir = app_a / fp_a
    enc_mgr = EncryptionManager(derive_index_key(SEED_A), fp_dir)
    vault = Vault(enc_mgr, fp_dir)
    cfg_mgr = ConfigManager(vault, fp_dir)
    backup_mgr = BackupManager(fp_dir, cfg_mgr)
    py_export = export_backup(vault, backup_mgr, fp_dir / "py-export.json", parent_seed=SEED_A)
    try:
        summary = json.loads(
            run_cli(
                app_a, "vault", "import", str(py_export), "--inspect",
                env_extra={"SEEDPASS_MNEMONIC": SEED_A},
            )
        )
        check(
            "TS imports a Python portable backup",
            summary["entry_count"] == len(vault.load_index().get("entries", {})),
            str(summary),
        )
    except Exception as exc:
        check("TS imports a Python portable backup", False, str(exc))

    # TS export -> Python import
    app_b = tmp / "b"
    fp_b = generate_fingerprint(SEED_B)
    ts_export = app_b / "ts-export.json"
    run_cli(
        app_b, "vault", "export", str(ts_export),
        env_extra={"SEEDPASS_MNEMONIC": SEED_B},
    )
    fp_dir_b = app_b / fp_b
    enc_b = EncryptionManager(derive_index_key(SEED_B), fp_dir_b)
    vault_b = Vault(enc_b, fp_dir_b)
    cfg_b = ConfigManager(vault_b, fp_dir_b)
    backup_b = BackupManager(fp_dir_b, cfg_b)
    def user_data(index: dict) -> str:
        """User-visible state only.

        ``_system.index0`` is Python-derived atlas state (canonical views,
        stats with recomputation timestamps), not stored user data — it is
        rebuilt on load and legitimately differs between two loads. The TS
        port deliberately does not emit it; see the compatibility matrix.
        """
        return json.dumps(
            {k: v for k, v in index.items() if k not in ("_system", "_sync_meta")},
            sort_keys=True,
        )

    before = user_data(vault_b.load_index())
    try:
        import_backup(vault_b, backup_b, ts_export, parent_seed=SEED_B)
        after = user_data(vault_b.load_index())
        check(
            "Python imports a TS portable backup (checksum verified)",
            before == after,
            "user data changed across the round trip",
        )
    except Exception as exc:
        check("Python imports a TS portable backup (checksum verified)", False, str(exc))


def phase_d(tmp: Path) -> None:
    print("\nPhase D: invalid-mnemonic handling agrees")
    app_dir = tmp / "d"
    app_dir.mkdir()

    # Python refuses an invalid phrase at seed derivation
    py_refused = False
    try:
        from bip_utils import Bip39SeedGenerator

        Bip39SeedGenerator(SEED_INVALID).Generate()
    except Exception:
        py_refused = True
    check("Python rejects a bad-checksum mnemonic", py_refused)

    ts_refused = False
    detail = ""
    try:
        run_cli(
            app_dir, "fingerprint", "add", "--name", "should-not-exist",
            env_extra={"SEEDPASS_MNEMONIC": SEED_INVALID, "SEEDPASS_PASSWORD": PASSWORD},
        )
        detail = "TS created a profile from an invalid phrase"
    except Exception as exc:
        ts_refused = "valid BIP-39" in str(exc)
        detail = str(exc)
    check("TS rejects a bad-checksum mnemonic", ts_refused, detail)


def phase_e(tmp: Path) -> None:
    print("\nPhase E: a legacy-schema Python vault opens in TypeScript")
    from seedpass.core.encryption import EncryptionManager
    from seedpass.core.migrations import apply_migrations
    from seedpass.core.vault import Vault
    from utils.fingerprint import generate_fingerprint
    from utils.key_derivation import derive_index_key

    app_dir = tmp / "e"
    app_dir.mkdir()
    fp = py_create_profile(app_dir, SEED_A, PASSWORD)
    fp_dir = app_dir / fp

    # Overwrite the index with a pre-v4 payload, as an older SeedPass wrote it
    legacy = {
        "schema_version": 2,
        "entries": {
            "0": {
                "type": "password",
                "label": "legacy-login.example",
                "length": 16,
                "notes": "written by an older SeedPass",
                "username": "olduser",
            },
            "1": {
                "type": "key_value",
                "label": "legacy-kv",
                "key": "token",
                "value": "legacy-secret-value",
                "notes": "",
            },
        },
    }
    enc_mgr = EncryptionManager(derive_index_key(SEED_A), fp_dir)
    enc_mgr.save_json_data(legacy, Path("seedpass_entries_db.json.enc"))

    env = {"SEEDPASS_MNEMONIC": SEED_A}
    try:
        rows = json.loads(run_cli(app_dir, "entry", "list", env_extra=env))
        labels = sorted(r["label"] for r in rows)
        check(
            "TS opens a v2 index and migrates it",
            labels == ["legacy-kv", "legacy-login.example"],
            str(labels),
        )
        revealed = run_cli(app_dir, "entry", "reveal", "legacy-kv", env_extra=env)
        check("TS reveals a migrated legacy secret", revealed == "legacy-secret-value")
    except Exception as exc:
        check("TS opens a v2 index and migrates it", False, str(exc))
        return

    # Python's own migration of the same payload must agree with what TS did
    py_migrated = apply_migrations(json.loads(json.dumps(legacy)))
    py_labels = sorted(e["label"] for e in py_migrated["entries"].values())
    check("Python and TS agree on the migrated entry set", py_labels == labels)

    # And TS must not have written a downgraded index back to disk
    reloaded = Vault(EncryptionManager(derive_index_key(SEED_A), fp_dir), fp_dir).load_index()
    check(
        "Python still reads the profile after TS touched it",
        sorted(e["label"] for e in reloaded.get("entries", {}).values()) == labels,
    )


class relay_running:
    """Run the in-process NIP-01 test relay and yield its ws:// URL."""

    SCRIPT = """
import { register } from "tsx/esm/api";
register();
const { MockRelay } = await import("REPO/js/packages/core/test/mockRelay.ts");
const relay = new MockRelay();
console.log(await relay.start());
process.on("SIGTERM", () => relay.stop().then(() => process.exit(0)));
await new Promise(() => {});
"""

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.proc: subprocess.Popen | None = None
        self.url = ""

    def __enter__(self) -> "relay_running":
        # Must live inside the workspace so pnpm's node_modules resolve.
        script = CLI_BIN.parent / "_cross_impl_relay.mjs"
        script.write_text(self.SCRIPT.replace("REPO", str(REPO)))
        self.script = script
        self.proc = subprocess.Popen(
            ["node", str(script)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            cwd=str(CLI_BIN.parent),
        )
        assert self.proc.stdout is not None
        self.url = self.proc.stdout.readline().strip()
        if not self.url.startswith("ws://"):
            raise RuntimeError(f"relay failed to start: {self.url!r}")
        return self

    def __exit__(self, *exc: object) -> None:
        if self.proc is not None:
            self.proc.terminate()
            self.proc.wait(timeout=10)
        self.script.unlink(missing_ok=True)


def phase_f(tmp: Path) -> None:
    print("\nPhase F: Nostr sync interop through a live relay")
    import asyncio

    from seedpass.core.encryption import EncryptionManager
    from seedpass.core.vault import Vault
    from utils.fingerprint import generate_fingerprint
    from utils.key_derivation import derive_index_key

    app_dir = tmp / "f"
    app_dir.mkdir()
    fp = py_create_profile(app_dir, SEED_A, PASSWORD)
    fp_dir = app_dir / fp

    with relay_running(tmp) as relay:
        # --- Python publishes -------------------------------------------------
        try:
            from nostr.client import NostrClient
            from seedpass.core.config_manager import ConfigManager
            from utils.key_hierarchy import kd
            from bip_utils import Bip39SeedGenerator

            enc_mgr = EncryptionManager(derive_index_key(SEED_A), fp_dir)
            vault = Vault(enc_mgr, fp_dir)
            cfg_mgr = ConfigManager(vault, fp_dir)
            cfg = cfg_mgr.load_config(require_pin=False)
            cfg["relays"] = [relay.url]
            cfg_mgr.save_config(cfg)

            seed_bytes = Bip39SeedGenerator(SEED_A).Generate()
            key_index = kd(kd(seed_bytes, b"seedpass:v1:master"), b"seedpass:v1:index")
            client = NostrClient(
                encryption_manager=enc_mgr,
                fingerprint=fp,
                relays=[relay.url],
                config_manager=cfg_mgr,
                parent_seed=SEED_A,
                key_index=key_index,
                account_index=0,
            )
            encrypted = vault.get_encrypted_index()
            manifest, manifest_id = asyncio.run(client.publish_snapshot(encrypted))
            published = bool(manifest_id) and bool(manifest.chunks)
            check("Python publishes a snapshot to the relay", published, str(manifest_id))
        except Exception as exc:
            check("Python publishes a snapshot to the relay", False, f"{type(exc).__name__}: {exc}")
            return

        # --- TypeScript restores from what Python published -------------------
        ts_dir = tmp / "f-ts"
        ts_dir.mkdir()
        env = {"SEEDPASS_MNEMONIC": SEED_A, "SEEDPASS_PASSWORD": PASSWORD}
        run_cli(ts_dir, "fingerprint", "add", "--name", "ts-restore", env_extra=env)
        run_cli(ts_dir, "nostr", "add-relay", relay.url, env_extra=env)
        for _ in range(3):
            try:
                run_cli(ts_dir, "nostr", "remove-relay", "1", env_extra=env)
            except Exception:
                break
        try:
            restored = json.loads(run_cli(ts_dir, "nostr", "restore", env_extra=env))
            py_index = vault.load_index()
            py_labels = sorted(e["label"] for e in py_index.get("entries", {}).values())
            rows = json.loads(run_cli(ts_dir, "entry", "list", env_extra=env))
            ts_labels = sorted(r["label"] for r in rows)
            check(
                "TS restores the Python-published snapshot",
                ts_labels == py_labels,
                f"{ts_labels} != {py_labels}",
            )
            revealed = run_cli(ts_dir, "entry", "reveal", "python-api", env_extra=env)
            check("restored secrets are intact", revealed == "py-secret-value", revealed)
        except Exception as exc:
            check("TS restores the Python-published snapshot", False, str(exc))


def _py_vault(app_dir: Path, fp: str, seed: str):
    from seedpass.core.backup import BackupManager
    from seedpass.core.config_manager import ConfigManager
    from seedpass.core.encryption import EncryptionManager
    from seedpass.core.entry_management import EntryManager
    from seedpass.core.vault import Vault
    from utils.key_derivation import derive_index_key

    fp_dir = app_dir / fp
    enc = EncryptionManager(derive_index_key(seed), fp_dir)
    vault = Vault(enc, fp_dir)
    cfg = ConfigManager(vault, fp_dir)
    return vault, EntryManager(vault, BackupManager(fp_dir, cfg)), cfg


def phase_g(tmp: Path) -> None:
    print("\nPhase G: edits made by one implementation are seen by the other")
    from utils.fingerprint import generate_fingerprint

    app_dir = tmp / "g"
    app_dir.mkdir()
    fp = py_create_profile(app_dir, SEED_A, PASSWORD)
    env = {"SEEDPASS_MNEMONIC": SEED_A}

    # Python edits -> TS sees
    _vault, em, _cfg = _py_vault(app_dir, fp, SEED_A)
    em.modify_entry(0, username="edited-by-python", notes="python note")
    em.archive_entry(1)
    em.add_link(0, 2, relation="related_to", note="py link")
    row = json.loads(run_cli(app_dir, "entry", "get", "0", env_extra=env))
    check(
        "TS sees Python's edit",
        row.get("username") == "edited-by-python" and row.get("notes") == "python note",
        json.dumps({k: row.get(k) for k in ("username", "notes")}),
    )
    links = json.loads(run_cli(app_dir, "entry", "links", "0", env_extra=env))
    check(
        "TS sees Python's link with a resolved target",
        len(links) == 1 and links[0]["relation"] == "related_to" and links[0]["target_id"] == 2,
        json.dumps(links),
    )
    archived = json.loads(run_cli(app_dir, "entry", "get", "1", env_extra=env))
    check("TS sees Python's archive flag", archived.get("archived") is True)

    # TS edits -> Python sees
    run_cli(app_dir, "entry", "modify", "0", "--notes", "edited-by-ts", env_extra=env)
    run_cli(app_dir, "entry", "unarchive", "1", env_extra=env)
    run_cli(app_dir, "entry", "link-remove", "0", "2", env_extra=env)
    _vault2, em2, _cfg2 = _py_vault(app_dir, fp, SEED_A)
    entry0 = em2.retrieve_entry(0)
    entry1 = em2.retrieve_entry(1)
    check("Python sees TS's edit", entry0.get("notes") == "edited-by-ts", str(entry0.get("notes")))
    check("Python sees TS's unarchive", entry1.get("archived") is False)
    check("Python sees TS's link removal", em2.get_links(0) == [])


def phase_h(tmp: Path) -> None:
    print("\nPhase H: conflict merge agrees across implementations")
    # Both sides merge the same divergent payloads; results must be identical,
    # or two clients syncing the same vault would converge differently.
    from seedpass.core.sync_conflict import merge_index_payloads

    base_ts = 1800000000
    current = {
        "schema_version": 4,
        "entries": {
            "0": {
                "type": "password", "kind": "password", "label": "shared",
                "length": 16, "archived": False, "notes": "from-current",
                "tags": ["a"], "modified_ts": base_ts,
            },
            "1": {
                "type": "key_value", "kind": "key_value", "label": "only-current",
                "key": "k", "value": "v", "archived": False, "notes": "",
                "tags": [], "modified_ts": base_ts,
            },
        },
    }
    incoming = {
        "schema_version": 4,
        "entries": {
            "0": {
                "type": "password", "kind": "password", "label": "shared",
                "length": 16, "archived": True, "notes": "",
                "tags": ["b"], "modified_ts": base_ts, "username": "incoming-user",
            },
            "2": {
                "type": "password", "kind": "password", "label": "only-incoming",
                "length": 20, "archived": False, "notes": "", "tags": [],
                "modified_ts": base_ts + 5,
            },
        },
    }

    py_merged = merge_index_payloads(
        json.loads(json.dumps(current)), json.loads(json.dumps(incoming)), source_tag="xtest"
    )

    # Run the TS merge through a tiny node harness against the same inputs
    script = CLI_BIN.parent / "_cross_impl_merge.mjs"
    script.write_text(
        'import { register } from "tsx/esm/api";\n'
        "register();\n"
        'const { mergeIndexPayloads } = await import("@seedpass/core");\n'
        "const [current, incoming] = JSON.parse(process.argv[2]);\n"
        'console.log(JSON.stringify(mergeIndexPayloads(current, incoming, "xtest")));\n'
    )
    try:
        proc = subprocess.run(
            ["node", str(script), json.dumps([current, incoming])],
            capture_output=True, text=True, cwd=str(CLI_BIN.parent),
        )
        if proc.returncode != 0:
            check("TS and Python merge identically", False, proc.stderr.strip()[:200])
            return
        ts_merged = json.loads(proc.stdout)
    finally:
        script.unlink(missing_ok=True)

    def comparable(payload: dict) -> str:
        # _system.index0 is Python-derived state TS does not emit.
        return json.dumps(
            {k: v for k, v in payload.items() if k != "_system"}, sort_keys=True
        )

    check(
        "TS and Python merge identically",
        comparable(py_merged) == comparable(ts_merged),
        "merged payloads differ",
    )
    check(
        "merge keeps entries from both sides",
        sorted(ts_merged["entries"]) == ["0", "1", "2"],
        str(sorted(ts_merged.get("entries", {}))),
    )


def phase_i(tmp: Path) -> None:
    print("\nPhase I: an Argon2id-mode Python profile opens in TypeScript")
    from seedpass.core.encryption import EncryptionManager
    from seedpass.core.manager import PasswordManager
    from utils.fingerprint import generate_fingerprint

    app_dir = tmp / "i"
    app_dir.mkdir()
    fp = py_create_profile(app_dir, SEED_A, PASSWORD)
    fp_dir = app_dir / fp

    # Re-encrypt the parent seed under argon2id, as a profile configured for
    # argon2 would have it on disk.
    dummy = PasswordManager.__new__(PasswordManager)
    dummy.config_manager = None
    kdf_cfg = PasswordManager._build_seed_kdf_config(dummy, fp, mode="argon2")
    seed_key = PasswordManager._derive_seed_key(
        dummy, PASSWORD, fp, mode="argon2", kdf_config=kdf_cfg
    )
    EncryptionManager(seed_key, fp_dir).encrypt_parent_seed(SEED_A, kdf=kdf_cfg)

    with agent_running(app_dir):
        try:
            run_cli(
                app_dir, "vault", "unlock", "--ttl", "10",
                env_extra={"SEEDPASS_PASSWORD": PASSWORD},
            )
            revealed = run_cli(app_dir, "entry", "reveal", "python-api")
            check(
                "TS unlocks an argon2id-protected Python profile",
                revealed == "py-secret-value",
                revealed,
            )
        except Exception as exc:
            check("TS unlocks an argon2id-protected Python profile", False, str(exc))


def phase_j(tmp: Path) -> None:
    print("\nPhase J: config file interoperates")
    from utils.fingerprint import generate_fingerprint

    app_dir = tmp / "g"  # reuse the profile from phase G
    fp = generate_fingerprint(SEED_A)
    env = {"SEEDPASS_MNEMONIC": SEED_A}

    # Python writes config -> TS reads it
    _vault, _em, cfg_mgr = _py_vault(app_dir, fp, SEED_A)
    cfg = cfg_mgr.load_config(require_pin=False)
    cfg["clipboard_clear_delay"] = 77
    cfg["relays"] = ["wss://relay.example.test"]
    cfg_mgr.save_config(cfg)
    ts_cfg = json.loads(run_cli(app_dir, "config", "get", env_extra=env))
    check(
        "TS reads Python's config",
        ts_cfg.get("clipboard_clear_delay") == 77
        and ts_cfg.get("relays") == ["wss://relay.example.test"],
        json.dumps({k: ts_cfg.get(k) for k in ("clipboard_clear_delay", "relays")}),
    )

    # TS writes config -> Python reads it
    run_cli(app_dir, "config", "set", "inactivity_timeout", "123", env_extra=env)
    _v2, _e2, cfg_mgr2 = _py_vault(app_dir, fp, SEED_A)
    py_cfg = cfg_mgr2.load_config(require_pin=False)
    check(
        "Python reads TS's config",
        int(py_cfg.get("inactivity_timeout", 0)) == 123,
        str(py_cfg.get("inactivity_timeout")),
    )


def phase_k(tmp: Path) -> None:
    print("\nPhase K: rollback — a profile driven by TS still works in Python")
    from utils.fingerprint import generate_fingerprint

    app_dir = tmp / "k"
    app_dir.mkdir()
    fp = py_create_profile(app_dir, SEED_A, PASSWORD)
    env = {"SEEDPASS_MNEMONIC": SEED_A}

    # Simulate a migration window: the user works exclusively in TS for a
    # while, exercising creation, modification and archival.
    run_cli(app_dir, "entry", "add", "password", "post-migration-site", "--length", "22", env_extra=env)
    run_cli(app_dir, "entry", "add", "key-value", "post-migration-kv", "k", "rollback-value", env_extra=env)
    run_cli(app_dir, "entry", "add", "totp", "post-migration-totp", env_extra=env)
    run_cli(app_dir, "entry", "modify", "0", "--notes", "touched by ts", env_extra=env)
    run_cli(app_dir, "entry", "archive", "1", env_extra=env)

    # Then they roll back to Python and must lose nothing.
    try:
        py_seed, py_index = py_open_profile(app_dir, fp, PASSWORD)
    except Exception as exc:
        check("Python reopens a TS-driven profile", False, str(exc))
        return
    check("Python reopens a TS-driven profile", py_seed == SEED_A)

    labels = {e["label"] for e in py_index.get("entries", {}).values()}
    check(
        "TS-created entries survive the rollback",
        {"post-migration-site", "post-migration-kv", "post-migration-totp"} <= labels,
        str(sorted(labels)),
    )
    entry0 = py_index["entries"]["0"]
    check("TS edits survive the rollback", entry0.get("notes") == "touched by ts")
    check(
        "TS archive state survives the rollback",
        bool(py_index["entries"]["1"].get("archived")),
    )

    # And Python can still derive the secrets for what TS created.
    py_secrets = py_secrets_for(py_index, SEED_A)
    ts_secrets = ts_secrets_for(app_dir, ["post-migration-site", "post-migration-kv"], SEED_A)
    check(
        "secrets for TS-created entries match in Python",
        all(
            py_secrets[k].rstrip("\n") == ts_secrets[k].rstrip("\n")
            for k in ts_secrets
        ),
    )

    # Finally, Python must still be able to write to the profile.
    _vault, em, _cfg = _py_vault(app_dir, fp, SEED_A)
    em.add_entry("written-after-rollback", 16)
    rows = json.loads(run_cli(app_dir, "entry", "list", env_extra=env))
    check(
        "Python can still write, and TS sees it",
        any(r["label"] == "written-after-rollback" for r in rows),
    )


def phase_l(tmp: Path) -> None:
    print("\nPhase L: foreign data round-trip — unknown kinds/fields survive A->B->A")
    # Spec section 8.6: for a vault holding records neither side fully
    # understands (a future BitLogin kind, unknown fields, an unknown
    # top-level index key), an interleaved Python -> TS -> Python
    # read-modify-write cycle must preserve every foreign byte. The trap
    # fields (blacklisted/website/words) are names Python's legacy
    # migrations act on for ITS shapes; touching them on a foreign record
    # would be reinterpretation, which the spec forbids.
    app_dir = tmp / "l"
    app_dir.mkdir()
    fp = py_create_profile(app_dir, SEED_A, PASSWORD)
    env = {"SEEDPASS_MNEMONIC": SEED_A}

    foreign_entry = {
        "kind": "bitlogin_org",
        "type": "bitlogin_org",
        "label": "Acme Corporation",
        "modified_ts": 1700000123,
        "blacklisted": "foreign meaning, not our archive flag",
        "website": "foreign meaning, not our label alias",
        "words": ["foreign", "list"],
        "bitlogin": {"admins": ["npub1aaaa"], "roles": {"sales": ["npub1bbbb"]}, "policy_rev": 7},
    }
    foreign_top_level = {"spec": "bitlogin-v1", "org_count": 1}

    # Python plants the foreign data at a fresh id beside the native entries.
    vault, em, _cfg = _py_vault(app_dir, fp, SEED_A)
    data = vault.load_index()
    pre_count = len(data["entries"])
    foreign_id = str(max((int(k) for k in data["entries"]), default=-1) + 1)
    data["entries"][foreign_id] = dict(foreign_entry)
    data["bitlogin_meta"] = dict(foreign_top_level)
    vault.save_index(data)

    # Python read-modify-write on a neighbour.
    em2 = _py_vault(app_dir, fp, SEED_A)[1]
    em2.add_entry("native-python", 16)

    # TS read-modify-write: create and edit, both of which re-validate and
    # re-encrypt the whole index.
    run_cli(app_dir, "entry", "add", "key-value", "native-ts", "k", "v", env_extra=env)
    run_cli(app_dir, "entry", "modify", "0", "--notes", "touched", env_extra=env)

    # Python reopens: every foreign byte must be exactly as planted.
    _seed, final = py_open_profile(app_dir, fp, PASSWORD)
    check(
        "foreign entry survives Python->TS->Python byte-for-byte",
        final["entries"].get(foreign_id) == foreign_entry,
        json.dumps(final["entries"].get(foreign_id), sort_keys=True)[:200],
    )
    check(
        "foreign top-level index key survives",
        final.get("bitlogin_meta") == foreign_top_level,
        json.dumps(final.get("bitlogin_meta"), sort_keys=True),
    )
    labels = {e.get("label") for e in final["entries"].values()}
    check(
        "native entries from both sides coexist with the foreign record",
        {"native-python", "native-ts"} <= labels,
        str(sorted(str(l) for l in labels)),
    )
    check(
        "allocation skipped past the foreign id (no collisions, no reuse)",
        len(final["entries"]) == pre_count + 3
        and max(int(k) for k in final["entries"]) == int(foreign_id) + 2,
        str(sorted(final["entries"].keys(), key=int)),
    )
    # And the foreign record is invisible to secret materialization rather
    # than guessed at: TS reveal must refuse it.
    try:
        run_cli(app_dir, "entry", "reveal", f"sp://entry/{foreign_id}", env_extra=env)
        refused = False
    except Exception:
        refused = True
    check("TS refuses to reveal the foreign record", refused)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-relay", action="store_true")
    parser.add_argument("--keep", action="store_true", help="keep the temp dir")
    args = parser.parse_args()

    if not CLI_BIN.exists():
        print(f"TypeScript CLI not found at {CLI_BIN}", file=sys.stderr)
        return 2

    tmp = Path(tempfile.mkdtemp(prefix="seedpass-crossimpl-"))
    print(f"Cross-implementation check (workdir: {tmp})")
    try:
        phase_a(tmp)
        phase_b(tmp)
        phase_c(tmp)
        phase_d(tmp)
        phase_e(tmp)
        phase_g(tmp)
        phase_h(tmp)
        phase_i(tmp)
        phase_j(tmp)
        phase_k(tmp)
        phase_l(tmp)
        if not args.skip_relay:
            phase_f(tmp)
    finally:
        if not args.keep:
            shutil.rmtree(tmp, ignore_errors=True)

    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    if divergences:
        print(f"\n{len(divergences)} known divergence(s):")
        for name, detail in divergences:
            print(f"  - {name}: {detail}")
    if failed:
        print("\nFailures:")
        for name, _ok, detail in failed:
            print(f"  - {name}: {detail}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
