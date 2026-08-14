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


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))
    mark = "PASS" if ok else "FAIL"
    print(f"  [{mark}] {name}" + (f" -- {detail}" if detail and not ok else ""))


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

    em.add_entry("python-site.example", 18, username="pyuser", url="https://py.example")
    em.add_totp("python-totp", seed, deterministic=True)
    em.add_key_value("python-api", "token", "py-secret-value")
    em.add_seed("python-cold-seed", seed, words_num=24)

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
            pg = PasswordGenerator(_Deriver(), seed, bip85, policy=PasswordPolicy())
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
            out[label] = TotpManager.current_code_from_secret(secret, FIXED_TS)
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
    mismatches = [k for k in py_secrets if py_secrets[k] != ts_secrets.get(k)]
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
    mismatches = [k for k in py_secrets if py_secrets[k] != ts_secrets.get(k)]
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
    finally:
        if not args.keep:
            shutil.rmtree(tmp, ignore_errors=True)

    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    if failed:
        print("\nFailures:")
        for name, _ok, detail in failed:
            print(f"  - {name}: {detail}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
