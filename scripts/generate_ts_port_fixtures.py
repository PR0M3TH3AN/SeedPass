#!/usr/bin/env python3
"""Generate deterministic parity fixtures for the TypeScript port.

Writes JSON fixture files to js/packages/test-vectors/fixtures/. The
TypeScript core must reproduce every expected output byte-for-byte; see
docs/typescript_web_extension_port_plan.md sections 6, 8 and 21.

Safety: every fixture derives from the public BIP-39 test mnemonics below.
Never point this script at a real profile or seed.

Determinism: running this twice on the same commit must produce identical
bytes. Anything time- or randomness-dependent (entry timestamps, the vault
fixture nonce, KDF salts) is pinned to fixed values. The pinned nonce/salt
are FIXTURE-ONLY conveniences — production code draws them from os.urandom.

Usage:
    .venv/bin/python scripts/generate_ts_port_fixtures.py
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from bip_utils import Bip39SeedGenerator  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

from local_bip85.bip85 import BIP85  # noqa: E402
from nostr.coincurve_keys import Keys  # noqa: E402
from nostr.key_manager import NOSTR_KEY_APP_ID  # noqa: E402
from seedpass.core.password_generation import (  # noqa: E402
    CURRENT_PASSWORD_GEN_VERSION,
    LEGACY_PASSWORD_GEN_VERSION,
    PasswordGenerator,
    PasswordPolicy,
)
from seedpass.core.totp import TotpManager  # noqa: E402
from utils.fingerprint import generate_fingerprint  # noqa: E402
from utils.key_derivation import derive_index_key, derive_totp_secret  # noqa: E402

FIXTURES_DIR = REPO / "js" / "packages" / "test-vectors" / "fixtures"
FIXTURE_VERSION = 1
FIXED_UNIX = 1700000000  # 2023-11-14T22:13:20Z — pins entry timestamps

# Public, well-known BIP-39 test vectors. Never real funds, never a real vault.
MNEMONICS = {
    "abandon12": (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    ),
    "legal12": (
        "legal winner thank year wave sausage worth useful "
        "legal winner thank yellow"
    ),
    "zoo24": (
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo "
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"
    ),
}
PRIMARY = "abandon12"

POLICIES = {
    "default": {},
    "exclude_ambiguous": {"exclude_ambiguous": True},
    "safe_special": {"special_mode": "safe"},
    "no_special": {"include_special_chars": False},
    "custom_special": {"allowed_special_chars": "!@#"},
    "high_minima": {
        "min_uppercase": 5,
        "min_lowercase": 5,
        "min_digits": 5,
        "min_special": 5,
    },
}

# (policy, length, index) — lengths cross the 32-byte v1 stream-wrap boundary
PASSWORD_CASES = [
    ("default", 8, 0),
    ("default", 16, 0),
    ("default", 16, 1),
    ("default", 16, 7),
    ("default", 16, 4095),
    ("default", 20, 3),
    ("default", 32, 2),
    ("default", 33, 2),
    ("default", 64, 5),
    ("default", 128, 11),
    ("exclude_ambiguous", 16, 0),
    ("exclude_ambiguous", 40, 2),
    ("safe_special", 16, 0),
    ("safe_special", 40, 2),
    ("no_special", 16, 0),
    ("no_special", 40, 2),
    ("custom_special", 16, 0),
    ("high_minima", 24, 0),
]


class _SeedDeriver:
    """Mirrors EncryptionManager.derive_seed_from_mnemonic without a vault."""

    def derive_seed_from_mnemonic(self, mnemonic, passphrase=""):
        return Bip39SeedGenerator(mnemonic).Generate(passphrase)


def _write(name: str, data: dict) -> None:
    path = FIXTURES_DIR / name
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    print(f"wrote {path.relative_to(REPO)}")


def _bip85(mnemonic: str) -> BIP85:
    return BIP85(Bip39SeedGenerator(mnemonic).Generate())


def gen_bip39() -> dict:
    cases = []
    for mid, mnemonic in MNEMONICS.items():
        seed = Bip39SeedGenerator(mnemonic).Generate()
        cases.append(
            {
                "id": mid,
                "mnemonic": mnemonic,
                "passphrase": "",
                "seed_hex": seed.hex(),
            }
        )
    return {"description": "BIP-39 mnemonic -> 64-byte seed", "cases": cases}


def gen_bip85_entropy() -> dict:
    cases = []
    specs = [
        # (app_no, index, entropy_bytes, word_count) — word_count only for 39
        (32, 0, 64, None),
        (32, 1, 64, None),
        (32, 0, 32, None),
        (39, 0, 16, 12),
        (39, 0, 32, 24),
        (39, 3, 16, 12),
        (NOSTR_KEY_APP_ID, 0, 32, None),
    ]
    for mid in ("abandon12", "zoo24"):
        bip85 = _bip85(MNEMONICS[mid])
        for app_no, index, nbytes, word_count in specs:
            entropy = bip85.derive_entropy(
                index=index,
                entropy_bytes=nbytes,
                app_no=app_no,
                word_count=word_count,
            )
            cases.append(
                {
                    "mnemonic_id": mid,
                    "app_no": app_no,
                    "index": index,
                    "entropy_bytes": nbytes,
                    "word_count": word_count,
                    "entropy_hex": entropy.hex(),
                }
            )
    return {
        "description": (
            "BIP-85 entropy: BIP32-SLIP10-secp256k1 path derivation, then "
            "HMAC-SHA512(key=b'bip-entropy-from-k', child_privkey)[:entropy_bytes]. "
            "Paths: app 39 -> m/83696968'/39'/0'/{word_count}'/{index}'; "
            "app 32 -> m/83696968'/32'/{index}'; "
            "other -> m/83696968'/{app_no}'/{index}'"
        ),
        "cases": cases,
    }


def gen_passwords(gen_version: int) -> dict:
    cases = []
    for mid in (PRIMARY,):
        mnemonic = MNEMONICS[mid]
        bip85 = _bip85(mnemonic)
        for policy_name, length, index in PASSWORD_CASES:
            policy = PasswordPolicy(**POLICIES[policy_name])
            pg = PasswordGenerator(_SeedDeriver(), mnemonic, bip85, policy=policy)
            password = pg.generate_password(
                length=length, index=index, gen_version=gen_version
            )
            cases.append(
                {
                    "mnemonic_id": mid,
                    "policy": policy_name,
                    "policy_params": POLICIES[policy_name],
                    "length": length,
                    "index": index,
                    "password": password,
                }
            )
    return {
        "description": f"Deterministic password derivation, gen_version={gen_version}",
        "gen_version": gen_version,
        "cases": cases,
    }


def gen_totp() -> dict:
    cases = []
    for mid in (PRIMARY, "zoo24"):
        mnemonic = MNEMONICS[mid]
        for index in (0, 1, 7):
            secret = derive_totp_secret(mnemonic, index)
            codes = {
                str(ts): TotpManager.current_code_from_secret(secret, ts)
                for ts in (0, FIXED_UNIX, FIXED_UNIX + 30)
            }
            cases.append(
                {
                    "mnemonic_id": mid,
                    "index": index,
                    "secret_b32": secret,
                    "period": 30,
                    "digits": 6,
                    "codes_at": codes,
                }
            )
    return {
        "description": (
            "TOTP secret derivation: path m/83696968'/39'/1414485072'/{index}' "
            "(1414485072 = 0x544F5450 = int.from_bytes(b'TOTP')), entropy = "
            "HMAC-SHA512(b'bip-entropy-from-k', k), secret = "
            "base32(SHA256(entropy[:32])[:20]); codes are RFC 6238 SHA-1 6-digit"
        ),
        "cases": cases,
    }


def gen_nostr_keys() -> dict:
    cases = []
    for mid in (PRIMARY, "legal12"):
        bip85 = _bip85(MNEMONICS[mid])
        for index in (0, 1, 7):
            entropy = bip85.derive_entropy(
                index=index, entropy_bytes=32, app_no=NOSTR_KEY_APP_ID
            )
            keys = Keys(priv_k=entropy.hex())
            cases.append(
                {
                    "mnemonic_id": mid,
                    "account_index": index,
                    "private_key_hex": keys.private_key_hex(),
                    "public_key_hex": keys.public_key_hex(),
                    "npub": Keys.hex_to_bech32(keys.public_key_hex(), "npub"),
                    "nsec": Keys.hex_to_bech32(keys.private_key_hex(), "nsec"),
                }
            )
    return {
        "description": (
            "Nostr keys: BIP-85 app 1237, 32 bytes -> secp256k1 private key; "
            "public key is x-only (compressed pubkey minus prefix byte); "
            "npub/nsec are bech32"
        ),
        "cases": cases,
    }


def gen_managed_seeds() -> dict:
    cases = []
    for mid in (PRIMARY, "zoo24"):
        bip85 = _bip85(MNEMONICS[mid])
        for words in (12, 24):
            for index in (0, 1):
                child = bip85.derive_mnemonic(index=index, words_num=words)
                cases.append(
                    {
                        "mnemonic_id": mid,
                        "words": words,
                        "index": index,
                        "child_mnemonic": child,
                        "child_fingerprint": generate_fingerprint(child),
                    }
                )
    return {
        "description": (
            "BIP-85 child mnemonics (managed accounts / derived seed phrases), "
            "BIP-39 English wordlist"
        ),
        "cases": cases,
    }


def gen_fingerprints() -> dict:
    cases = [
        {
            "mnemonic_id": mid,
            "mnemonic": mnemonic,
            "fingerprint": generate_fingerprint(mnemonic),
        }
        for mid, mnemonic in MNEMONICS.items()
    ]
    # Normalization: fingerprint input is strip().lower()
    cases.append(
        {
            "mnemonic_id": "abandon12-mixed-case-padded",
            "mnemonic": "  " + MNEMONICS[PRIMARY].upper() + "  ",
            "fingerprint": generate_fingerprint("  " + MNEMONICS[PRIMARY].upper() + "  "),
        }
    )
    return {
        "description": (
            "Profile fingerprint: SHA256(mnemonic.strip().lower()) hex, "
            "first 16 chars, uppercased"
        ),
        "cases": cases,
    }


def gen_index_keys() -> dict:
    cases = []
    for mid, mnemonic in MNEMONICS.items():
        key_b64 = derive_index_key(mnemonic).decode()
        cases.append({"mnemonic_id": mid, "index_key_urlsafe_b64": key_b64})
    return {
        "description": (
            "Vault index key (seed-only mode): seed = BIP39(mnemonic); "
            "master = HKDF-SHA256(seed, salt=None, info=b'seedpass:v1:master'); "
            "key = HKDF-SHA256(master, salt=None, info=b'seedpass:v1:storage'); "
            "urlsafe base64"
        ),
        "cases": cases,
    }


def _build_entries_index() -> dict:
    """Build a real entries index with one entry of each kind, timestamps pinned."""
    from seedpass.core.backup import BackupManager
    from seedpass.core.config_manager import ConfigManager
    from seedpass.core.entry_management import EntryManager
    from seedpass.core.encryption import EncryptionManager
    from seedpass.core.vault import Vault
    from utils.key_derivation import derive_key_from_password

    mnemonic = MNEMONICS[PRIMARY]

    # Pin every timestamp EntryManager writes
    EntryManager._now_unix = staticmethod(lambda: FIXED_UNIX)

    with tempfile.TemporaryDirectory() as tmp:
        dir_path = Path(tmp)
        fp = generate_fingerprint(mnemonic)
        seed_key = derive_key_from_password("fixture-password", fp)
        EncryptionManager(seed_key, dir_path).encrypt_parent_seed(mnemonic)

        index_key = derive_index_key(mnemonic)
        enc_mgr = EncryptionManager(index_key, dir_path)
        vault = Vault(enc_mgr, dir_path)
        cfg_mgr = ConfigManager(vault, dir_path)
        backup_mgr = BackupManager(dir_path, cfg_mgr)
        em = EntryManager(vault, backup_mgr)

        em.add_entry(
            "example.com",
            16,
            username="alice",
            url="https://example.com",
            notes="password note",
            tags=["web"],
        )
        em.add_totp("example-totp", mnemonic, deterministic=True, tags=["otp"])
        em.add_totp(
            "imported-totp",
            secret="JBSWY3DPEHPK3PXP",
            period=45,
            digits=8,
        )
        em.add_ssh_key("example-ssh", mnemonic, notes="ssh note")
        em.add_nostr_key("example-nostr", mnemonic)
        em.add_key_value("api-token", "token", "abc123", tags=["api"])
        em.add_document("example-doc", "hello fixture world", file_type="txt")
        em.add_seed("example-seed", mnemonic, words_num=24)
        em.add_managed_account("example-managed", mnemonic)
        em.add_pgp_key("example-pgp", mnemonic, user_id="fixture@example.com")

        index = vault.load_index()
        entries = {
            k: v for k, v in index.items() if k != "_system"
        }
        return entries


def gen_entries_and_vault() -> tuple[dict, dict]:
    entries = _build_entries_index()

    plaintext = json.dumps(entries, indent=2, sort_keys=True).encode()
    key = base64.urlsafe_b64decode(derive_index_key(MNEMONICS[PRIMARY]))
    # FIXTURE-ONLY fixed nonce so the blob is reproducible; production uses
    # os.urandom(12) per encryption (see EncryptionManager.encrypt_data).
    nonce = hashlib.sha256(b"seedpass-ts-fixture-nonce").digest()[:12]
    blob = b"V3|" + nonce + AESGCM(key).encrypt(nonce, plaintext, None)

    entries_fixture = {
        "description": (
            "Decrypted entries index (one entry of each kind), _system "
            "stripped, timestamps pinned to FIXED_UNIX"
        ),
        "fixed_unix": FIXED_UNIX,
        "mnemonic_id": PRIMARY,
        "entries": entries,
    }
    vault_fixture = {
        "description": (
            "Encrypted vault payload, format b'V3|' + nonce(12) + AES-GCM "
            "ciphertext+tag, key = raw bytes of index_key fixture. Nonce is "
            "fixed for fixture reproducibility only."
        ),
        "mnemonic_id": PRIMARY,
        "nonce_hex": nonce.hex(),
        "payload_b64": base64.b64encode(blob).decode(),
        "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
        "plaintext_canonical_json": "entries_index.json#entries (indent=2, sort_keys)",
    }
    return entries_fixture, vault_fixture


def gen_password_kdf() -> dict:
    from utils.key_derivation import (
        KdfConfig,
        derive_key_from_password,
        derive_key_from_password_argon2,
    )

    fp = generate_fingerprint(MNEMONICS[PRIMARY])
    pbkdf2_cases = []
    for password in ("fixture-password", "correct horse battery staple", "  pässwörd  "):
        for iterations in (50_000, 100_000):
            key = derive_key_from_password(password, fp, iterations=iterations)
            pbkdf2_cases.append(
                {
                    "password": password,
                    "fingerprint": fp,
                    "iterations": iterations,
                    "key_urlsafe_b64": key.decode(),
                }
            )

    argon2_cases = []
    for params in (
        {"time_cost": 2, "memory_cost": 64 * 1024, "parallelism": 8},
        {"time_cost": 1, "memory_cost": 8 * 1024, "parallelism": 1},
    ):
        kdf = KdfConfig(
            name="argon2id",
            version=1,
            params=params,
            salt_b64=base64.b64encode(b"fixture-salt-16b").decode(),
        )
        key = derive_key_from_password_argon2("fixture-password", kdf)
        argon2_cases.append(
            {
                "password": "fixture-password",
                "kdf": {
                    "name": kdf.name,
                    "version": kdf.version,
                    "params": kdf.params,
                    "salt_b64": kdf.salt_b64,
                },
                "key_urlsafe_b64": key.decode(),
            }
        )

    return {
        "description": (
            "Password-based key derivation. PBKDF2: NFKD-normalized+stripped "
            "password, salt = SHA256(fingerprint)[:16], PBKDF2-HMAC-SHA256, "
            "32 bytes, urlsafe b64. Argon2id: NFKD+strip, salt from config, "
            "hash_len 32, urlsafe b64. Salts pinned for fixtures only."
        ),
        "pbkdf2_cases": pbkdf2_cases,
        "argon2id_cases": argon2_cases,
    }


def gen_legacy_payloads() -> dict:
    from cryptography.fernet import Fernet

    mnemonic = MNEMONICS[PRIMARY]
    key_b64 = derive_index_key(mnemonic)
    raw_key = base64.urlsafe_b64decode(key_b64)
    fernet = Fernet(key_b64)

    plaintext = b'{"legacy": true, "hello": "fixture"}'
    iv = hashlib.sha256(b"seedpass-ts-fixture-fernet-iv").digest()[:16]
    token = fernet._encrypt_from_parts(plaintext, FIXED_UNIX, iv)

    nonce = hashlib.sha256(b"seedpass-ts-fixture-v2-nonce").digest()[:12]
    v2_gcm = b"V2:" + nonce + AESGCM(raw_key).encrypt(nonce, plaintext, None)
    v2_fernet = b"V2:" + token

    # Serialized parent-seed file: JSON {"kdf": ..., "ct": b64(V3 blob)},
    # encrypted with the password-derived key (not the index key).
    from utils.key_derivation import derive_key_from_password

    fp = generate_fingerprint(mnemonic)
    seed_key_b64 = derive_key_from_password("fixture-password", fp)
    seed_key = base64.urlsafe_b64decode(seed_key_b64)
    seed_nonce = hashlib.sha256(b"seedpass-ts-fixture-seed-nonce").digest()[:12]
    seed_ct = b"V3|" + seed_nonce + AESGCM(seed_key).encrypt(
        seed_nonce, mnemonic.encode(), None
    )
    kdf_dict = {
        "name": "pbkdf2-sha256",
        "version": 1,
        "params": {"iterations": 100000},
        "salt_b64": "",
    }
    wrapper = json.dumps(
        {"kdf": kdf_dict, "ct": base64.b64encode(seed_ct).decode()},
        separators=(",", ":"),
    ).encode()

    return {
        "description": (
            "Legacy/migration payload formats the TS port must read: raw "
            "Fernet token, V2-prefixed AES-GCM, V2-prefixed Fernet "
            "(wrong-header case), and the JSON kdf/ct file wrapper around a "
            "V3 blob. IVs/nonces/timestamps pinned for fixtures only."
        ),
        "mnemonic_id": PRIMARY,
        "plaintext_utf8": plaintext.decode(),
        "fernet_token_b64": base64.b64encode(token).decode(),
        "v2_gcm_payload_b64": base64.b64encode(v2_gcm).decode(),
        "v2_fernet_payload_b64": base64.b64encode(v2_fernet).decode(),
        "parent_seed_file": {
            "password": "fixture-password",
            "fingerprint": generate_fingerprint(mnemonic),
            "wrapper_b64": base64.b64encode(wrapper).decode(),
            "expected_seed_mnemonic_id": PRIMARY,
        },
    }


def _derive_key_index(mnemonic: str) -> bytes:
    from utils.key_hierarchy import kd

    seed = Bip39SeedGenerator(mnemonic).Generate()
    master = kd(seed, b"seedpass:v1:master")
    return kd(master, b"seedpass:v1:index")


def gen_nostr_snapshot(vault_payload_b64: str) -> dict:
    import gzip as gzip_mod
    import hmac as hmac_mod

    from nostr.snapshot import prepare_snapshot

    mnemonic = MNEMONICS[PRIMARY]
    encrypted = base64.b64decode(vault_payload_b64)

    # mtime=0 pins the gzip header; production uses current time, which only
    # affects the compressed bytes, not decompression.
    compressed = gzip_mod.compress(encrypted, mtime=0)
    limit = 800
    manifest, chunks = prepare_snapshot(encrypted, limit)
    # Re-chunk the pinned compression so chunk bytes/hashes are deterministic
    pinned_chunks = [compressed[i : i + limit] for i in range(0, len(compressed), limit)]
    metas = [
        {
            "id": f"seedpass-chunk-{i:04d}",
            "size": len(c),
            "hash": hashlib.sha256(c).hexdigest(),
            "event_id": None,
        }
        for i, c in enumerate(pinned_chunks)
    ]

    nonce = hashlib.sha256(b"seedpass-ts-fixture-manifest-nonce").digest()[:16]
    key_index = _derive_key_index(mnemonic)
    manifest_id = hmac_mod.new(
        key_index, b"manifest|" + nonce, hashlib.sha256
    ).hexdigest()

    manifest_json = json.dumps(
        {
            "ver": 1,
            "algo": "gzip",
            "chunks": metas,
            "delta_since": FIXED_UNIX,
            "nonce": base64.b64encode(nonce).decode(),
            "index0": None,
        }
    )

    return {
        "description": (
            "Nostr snapshot model: gzip(encrypted index) split into <=limit "
            "chunks; chunk id 'seedpass-chunk-%04d', sha256 hash; manifest "
            "kind 30070 (d-tag = manifest id), chunks kind 30071 (d-tag = "
            "chunk id, content = b64), deltas kind 30072. Manifest id = "
            "HMAC-SHA256(key_index, b'manifest|' + nonce) hex, key_index = "
            "HKDF chain master->'seedpass:v1:index'. gzip mtime pinned to 0 "
            "for the fixture."
        ),
        "mnemonic_id": PRIMARY,
        "event_kinds": {"manifest": 30070, "snapshot_chunk": 30071, "delta": 30072},
        "chunk_limit": limit,
        "encrypted_b64": vault_payload_b64,
        "compressed_b64": base64.b64encode(compressed).decode(),
        "chunks_b64": [base64.b64encode(c).decode() for c in pinned_chunks],
        "chunk_metas": metas,
        "key_index_hex": key_index.hex(),
        "manifest_nonce_b64": base64.b64encode(nonce).decode(),
        "manifest_id": manifest_id,
        "manifest_json": manifest_json,
        "unpinned_chunk_count": len(chunks),
    }


def _merge_case(name: str, current: dict, incoming: dict, source_tag: str) -> dict:
    import copy

    from seedpass.core.sync_conflict import merge_index_payloads

    merged = merge_index_payloads(
        copy.deepcopy(current), copy.deepcopy(incoming), source_tag=source_tag
    )
    return {
        "name": name,
        "current": current,
        "incoming": incoming,
        "source_tag": source_tag,
        "merged": merged,
    }


def gen_sync_merge() -> dict:
    t = FIXED_UNIX

    def entry(label: str, ts: int, **kw) -> dict:
        base = {
            "type": "password",
            "kind": "password",
            "label": label,
            "length": 16,
            "archived": False,
            "notes": "",
            "tags": [],
            "modified_ts": ts,
        }
        base.update(kw)
        return base

    cases = [
        _merge_case(
            "newer-incoming-wins",
            {"schema_version": 4, "entries": {"0": entry("site", t)}},
            {"schema_version": 4, "entries": {"0": entry("site-renamed", t + 10)}},
            "tag-newer",
        ),
        _merge_case(
            "older-incoming-loses",
            {"schema_version": 4, "entries": {"0": entry("site", t + 10)}},
            {"schema_version": 4, "entries": {"0": entry("site-old", t)}},
            "tag-older",
        ),
        _merge_case(
            "equal-ts-field-union",
            {
                "schema_version": 4,
                "entries": {
                    "0": entry("site", t, notes="", tags=["a", "c"], username="")
                },
            },
            {
                "schema_version": 4,
                "entries": {
                    "0": entry(
                        "site", t, notes="from-incoming", tags=["b", "a"],
                        username="alice", archived=True,
                    )
                },
            },
            "tag-equal",
        ),
        _merge_case(
            "incoming-delete-creates-tombstone",
            {"schema_version": 4, "entries": {"0": entry("site", t), "1": entry("keep", t)}},
            {
                "schema_version": 4,
                "entries": {"0": {**entry("site", t + 5), "_deleted": True}},
            },
            "tag-delete",
        ),
        _merge_case(
            "entry-newer-than-tombstone-survives",
            {
                "schema_version": 4,
                "entries": {},
                "_sync_meta": {
                    "tombstones": {
                        "0": {"deleted_ts": t, "entry_hash": "", "event_hash": "", "source": "x"}
                    }
                },
            },
            {"schema_version": 4, "entries": {"0": entry("revived", t + 20)}},
            "tag-revive",
        ),
        _merge_case(
            "tombstone-beats-older-entry",
            {
                "schema_version": 4,
                "entries": {},
                "_sync_meta": {
                    "tombstones": {
                        "0": {"deleted_ts": t + 20, "entry_hash": "", "event_hash": "", "source": "x"}
                    }
                },
            },
            {"schema_version": 4, "entries": {"0": entry("stale", t)}},
            "tag-stale",
        ),
        _merge_case(
            "tombstone-vs-tombstone-newer-wins",
            {
                "schema_version": 4,
                "entries": {},
                "_sync_meta": {
                    "tombstones": {
                        "0": {"deleted_ts": t + 1, "entry_hash": "aa", "event_hash": "", "source": "one"}
                    }
                },
            },
            {
                "schema_version": 4,
                "entries": {},
                "_sync_meta": {
                    "tombstones": {
                        "0": {"deleted_ts": t + 9, "entry_hash": "bb", "event_hash": "", "source": "two"}
                    }
                },
            },
            "tag-tt",
        ),
        _merge_case(
            "empty-current-adopts-incoming",
            {},
            {"schema_version": 4, "entries": {"3": entry("new", t)}},
            "tag-adopt",
        ),
    ]
    return {
        "description": (
            "merge_index_payloads parity cases. merged output includes the "
            "normalized empty _system.index0 skeleton and _sync_meta with "
            "strategy modified_ts_hash_tombstone_v2."
        ),
        "cases": cases,
    }


def gen_delta_replay() -> dict:
    import copy

    from seedpass.core.index0 import ensure_index0_payload
    from seedpass.core.sync_conflict import merge_index_payloads

    key = base64.urlsafe_b64decode(derive_index_key(MNEMONICS[PRIMARY]))
    t = FIXED_UNIX

    def entry(label: str, ts: int) -> dict:
        return {
            "type": "password", "kind": "password", "label": label,
            "length": 16, "archived": False, "notes": "", "tags": [],
            "modified_ts": ts,
        }

    snapshot_index = {"schema_version": 4, "entries": {"0": entry("base", t)}}
    delta1 = {"schema_version": 4, "entries": {"0": entry("base-renamed", t + 10), "1": entry("added", t + 10)}}
    delta2 = {"schema_version": 4, "entries": {"1": {**entry("added", t + 20), "_deleted": True}}}

    def encrypt(payload: dict, nonce_seed: bytes) -> bytes:
        nonce = hashlib.sha256(nonce_seed).digest()[:12]
        plaintext = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return b"V3|" + nonce + AESGCM(key).encrypt(nonce, plaintext, None)

    enc_deltas = [
        encrypt(delta1, b"seedpass-ts-fixture-delta-1"),
        encrypt(delta2, b"seedpass-ts-fixture-delta-2"),
    ]

    # Reproduce decrypt_and_save_index_from_nostr(merge=True) semantics
    state = ensure_index0_payload(copy.deepcopy(snapshot_index))
    for enc, payload in zip(enc_deltas, [delta1, delta2]):
        source_tag = hashlib.sha256(enc).hexdigest()[:16]
        incoming = ensure_index0_payload(copy.deepcopy(payload))
        state = merge_index_payloads(state, incoming, source_tag=source_tag)

    return {
        "description": (
            "Delta replay: start from a snapshot index, decrypt each V3 delta "
            "payload, merge in order with source_tag = "
            "sha256(encrypted_delta)[:16]. Nonces pinned (fixture-only)."
        ),
        "mnemonic_id": PRIMARY,
        "snapshot_index": snapshot_index,
        "delta_payloads_b64": [base64.b64encode(e).decode() for e in enc_deltas],
        "delta_plaintexts": [delta1, delta2],
        "final_state": state,
    }


def gen_portable_backup(entries: dict) -> dict:
    from utils.checksum import canonical_json_dumps, json_checksum

    mnemonic = MNEMONICS[PRIMARY]
    index_data = entries
    canonical = canonical_json_dumps(index_data)
    checksum = json_checksum(index_data)

    key = base64.urlsafe_b64decode(derive_index_key(mnemonic))
    nonce = hashlib.sha256(b"seedpass-ts-fixture-export-nonce").digest()[:12]
    payload = b"V3|" + nonce + AESGCM(key).encrypt(nonce, canonical.encode(), None)

    encrypted_wrapper = {
        "format_version": 1,
        "created_at": FIXED_UNIX,
        "fingerprint": generate_fingerprint(mnemonic),
        "encryption_mode": "seed-only",
        "cipher": "aes-gcm",
        "checksum": checksum,
        "payload": base64.b64encode(payload).decode(),
    }
    plaintext_wrapper = {
        "format_version": 1,
        "created_at": FIXED_UNIX,
        "fingerprint": generate_fingerprint(mnemonic),
        "encryption_mode": "none",
        "cipher": "none",
        "checksum": checksum,
        "payload": base64.b64encode(canonical.encode()).decode(),
    }

    return {
        "description": (
            "Portable backup wrapper (portable_backup.py, format_version 1). "
            "payload = V3 AES-GCM over canonical JSON of the index, key = "
            "index key of the parent seed; checksum = "
            "sha256(canonical_json(index)). Nonce/created_at pinned "
            "(fixture-only)."
        ),
        "mnemonic_id": PRIMARY,
        "index": index_data,
        "canonical_json_sha256": checksum,
        "encrypted_wrapper": encrypted_wrapper,
        "plaintext_wrapper": plaintext_wrapper,
    }


def gen_entry_secrets() -> dict:
    """Expected reveal values for the fixture vault, via the same low-level
    functions EntryManager retrieval uses."""
    from nostr.coincurve_keys import Keys
    from seedpass.core.password_generation import (
        PasswordGenerator,
        PasswordPolicy,
        derive_seed_phrase,
    )

    mnemonic = MNEMONICS[PRIMARY]
    bip85 = _bip85(mnemonic)

    # Entry 0: password, length 16, gen_version 2, derivation index 0
    pg = PasswordGenerator(_SeedDeriver(), mnemonic, bip85, policy=PasswordPolicy())
    password = pg.generate_password(length=16, index=0, gen_version=2)

    # Entry 1: deterministic TOTP, derivation index 0
    totp_secret = derive_totp_secret(mnemonic, 0)
    totp_code = TotpManager.current_code_from_secret(totp_secret, FIXED_UNIX)

    # Entry 4: nostr key entry — DEFAULT BIP-85 app 39 (not 1237)
    entropy = bip85.derive_entropy(index=4, entropy_bytes=32)
    nostr_keys = Keys(priv_k=entropy.hex())
    nsec = Keys.hex_to_bech32(nostr_keys.private_key_hex(), "nsec")
    npub = Keys.hex_to_bech32(nostr_keys.public_key_hex(), "npub")

    # Entry 7: seed entry, index 7, 24 words; entry 8: managed account, 12 words
    seed_phrase = derive_seed_phrase(bip85, 7, 24)
    managed_phrase = derive_seed_phrase(bip85, 8, 12)

    return {
        "description": (
            "Expected plaintext values for entries in entries_index.json, "
            "computed via the same functions EntryManager retrieval uses. "
            "Nostr entry keys use the DEFAULT BIP-85 app 39 path, unlike the "
            "sync client identity (app 1237)."
        ),
        "mnemonic_id": PRIMARY,
        "password_entry_0": password,
        "totp_entry_1_code_at": {str(FIXED_UNIX): totp_code},
        "nostr_entry_4": {"nsec": nsec, "npub": npub},
        "seed_entry_7_mnemonic": seed_phrase,
        "managed_entry_8_mnemonic": managed_phrase,
    }


def gen_kdf_metadata() -> dict:
    return {
        "description": (
            "Vault KDF metadata shapes the TS port must parse. Salts here are "
            "pinned for the fixture; production salts come from os.urandom."
        ),
        "current_kdf_version": 1,
        "configs": [
            {
                "name": "argon2id",
                "version": 1,
                "params": {"time_cost": 2, "memory_cost": 65536, "parallelism": 8},
                "salt_b64": base64.b64encode(b"fixture-salt-16b").decode(),
            },
            {
                "name": "pbkdf2-sha256",
                "version": 1,
                "params": {"iterations": 100000, "dklen": 32},
                "salt_note": "salt = SHA256(fingerprint)[:16] — deterministic",
            },
        ],
    }


def main() -> None:
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)

    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True
    ).stdout.strip()

    files: dict[str, dict] = {
        "bip39_seeds.json": gen_bip39(),
        "bip85_entropy.json": gen_bip85_entropy(),
        "passwords_v1.json": gen_passwords(LEGACY_PASSWORD_GEN_VERSION),
        "passwords_v2.json": gen_passwords(CURRENT_PASSWORD_GEN_VERSION),
        "totp.json": gen_totp(),
        "nostr_keys.json": gen_nostr_keys(),
        "managed_seeds.json": gen_managed_seeds(),
        "fingerprints.json": gen_fingerprints(),
        "index_keys.json": gen_index_keys(),
        "kdf_metadata.json": gen_kdf_metadata(),
        "password_kdf.json": gen_password_kdf(),
        "legacy_payloads.json": gen_legacy_payloads(),
    }
    entries_fixture, vault_fixture = gen_entries_and_vault()
    files["entries_index.json"] = entries_fixture
    files["vault_v3_payload.json"] = vault_fixture
    files["nostr_snapshot.json"] = gen_nostr_snapshot(vault_fixture["payload_b64"])
    files["portable_backup.json"] = gen_portable_backup(entries_fixture["entries"])
    files["entry_secrets.json"] = gen_entry_secrets()
    files["sync_merge.json"] = gen_sync_merge()
    files["delta_replay.json"] = gen_delta_replay()

    for name, data in files.items():
        data["fixture_version"] = FIXTURE_VERSION
        _write(name, data)

    manifest = {
        "fixture_version": FIXTURE_VERSION,
        "python_commit": commit,
        "generator": "scripts/generate_ts_port_fixtures.py",
        "redaction_policy": (
            "All fixtures derive from public BIP-39 test mnemonics "
            "(abandon.../legal.../zoo...). Secret-shaped outputs are "
            "generated test material, never from a live profile."
        ),
        "determinism": (
            "Byte-identical across runs on the same commit: timestamps pinned "
            "to fixed_unix, vault nonce and KDF salts pinned (fixture-only)."
        ),
        "files": sorted(files.keys()),
    }
    _write("manifest.json", manifest)


if __name__ == "__main__":
    main()
