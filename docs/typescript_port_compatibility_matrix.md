# TypeScript Port Compatibility Matrix

Status: living document. Update with every parity change.
Fixture source: `scripts/generate_ts_port_fixtures.py` (regenerate with
`.venv/bin/python scripts/generate_ts_port_fixtures.py`; output is
byte-deterministic per commit).
Parity suite: `js/packages/core/test/parity.test.ts` — runs in Node and a
jsdom (browser-like) environment via `pnpm test` in `js/`.

Statuses: **green** = fixture-verified byte-for-byte parity; **partial** =
subset verified; **todo** = not started; **n/a-first-slice** = out of scope
until a later milestone.

| Area | Priority | Status | Fixture file | Notes |
|---|---|---|---|---|
| BIP-39 mnemonic -> seed | P0 | green | `bip39_seeds.json` | 12/24-word public test vectors, empty passphrase. Passphrase cases TODO. |
| BIP-85 entropy derivation | P0 | green | `bip85_entropy.json` | Apps 32, 39, 1237; word-count path quirk (app 39 defaults word_count=entropy_bytes) reproduced. |
| Password derivation v1 (frozen) | P0 | green | `passwords_v1.json` | All 6 policies, lengths 8–128 crossing the 32-byte stream-wrap boundary, index up to 4095. Matches the frozen vectors in `src/tests/test_entropy_integrity.py`. |
| Password derivation v2 | P0 | green | `passwords_v2.json` | Same case grid as v1. |
| Fingerprints | P0 | green | `fingerprints.json` | Includes normalization case (strip + lower). Non-ASCII normalization unverified (Python `str.lower()` vs JS `toLowerCase()`); BIP-39 mnemonics are ASCII so not P0. |
| Vault index key (seed-only) | P0 | green | `index_keys.json` | HKDF-SHA256 chain, zero salt, urlsafe base64. |
| Vault V3 payload decrypt | P0 | green | `vault_v3_payload.json` | AES-256-GCM via WebCrypto; tamper-rejection tested. Fixture nonce is pinned (fixture-only). |
| Legacy V2/Fernet payload decrypt | P0 | green | `legacy_payloads.json` | Full `decrypt_data` fallback chain: V3 -> V2 GCM -> V2-header-over-Fernet -> raw Fernet. Decrypt-only by design. |
| Encrypted file wrapper (kdf/ct JSON) | P0 | green | `legacy_payloads.json` | `_serialize`/`_deserialize` parity incl. legacy bare-ciphertext fallback; parent-seed decrypt verified end-to-end from password. |
| Entry schema roundtrip | P0 | green | `entries_index.json` | Zod schemas for all 9 kinds validate the Python `EntryManager`-generated index and roundtrip it unchanged; future schema_version refused. Older-version migrations (0-3): todo. |
| TOTP secret derivation + codes | P1 | green | `totp.json` | Path child is `0x544F5450` (= `int.from_bytes(b"TOTP")`) — note: an earlier draft of this doc/code said 1414812756; correct value is 1414485072. RFC 6238 SHA-1 codes verified at fixed timestamps. |
| Nostr keys (app 1237) | P1 | green | `nostr_keys.json` | Private/public hex (x-only), npub, nsec. Legacy fingerprint-hash and app-0 derivations: todo. |
| Managed seeds (BIP-85 child mnemonics) | P0 | green | `managed_seeds.json` | 12/24 words from 12- and 24-word parents, plus child fingerprints. 18-word: untested (Python supports; add cases when needed). |
| Password KDF (PBKDF2-SHA256) | P0 | green | `password_kdf.json` | NFKD+strip normalization incl. a unicode/whitespace case; 50k and 100k iterations; fingerprint-derived salt. |
| Password KDF (Argon2id) | P0 | green | `password_kdf.json` | `@noble/hashes` argon2id (pure JS, audited family); default (t=2, m=64MiB, p=8) and light params verified. |
| KDF metadata parsing | P0 | green | `kdf_metadata.json`, `legacy_payloads.json` | KdfConfig schema with Python-default fallbacks. |
| SSH key derivation | P1 | todo | — | Ed25519 from BIP-85 app 32; PEM serialization parity risk. |
| PGP key derivation | P1/P2 | todo | — | Highest parity risk (PGPy serialization); import/roundtrip first. |
| Nostr snapshot chunk/manifest model | P0 | green | `nostr_snapshot.json` | Kinds 30070/30071/30072; gzip chunking, chunk-hash verify, reassembly of Python-produced chunks, manifest JSON parse, manifest id HMAC (key_index chain). Compressed bytes are deliberately not byte-pinned (deflate encoders differ); cross-decompression verified both ways. Relay WebSocket adapter: todo. |
| Deterministic conflict merge | P0 | green | `sync_merge.json` | Full `merge_index_payloads` port: ts precedence, canonical-hash tie-breaks (Python-compatible ensure_ascii canonical JSON), equal-ts field union incl. the `custom_fields: null` quirk, tombstone lifecycle, retention cap, `_sync_meta`. |
| Tombstones / delta replay | P0 | green | `delta_replay.json` | Encrypted V3 deltas decrypted and merged in order with `source_tag = sha256(payload)[:16]`, final state matches Python. |
| index0 content merge (`_system.index0`) | P2 | partial | — | Empty-skeleton normalization matches Python; merging populated index0 event logs throws loudly instead of silently dropping data. Full port belongs to the atlas milestone. |
| Nostr event layer (NIP-01 ids, BIP-340 sign/verify, framing) | P0 | green | `nostr_events.json` | Event ids match rust-nostr (Python nostr_sdk) fixtures byte-for-byte; fixture signatures verify in TS; TS-signed events reproduce the same ids and verify. REQ/EVENT/EOSE/OK/NOTICE/CLOSED framing round-trips. Fixture signatures are cached across generator runs (BIP-340 aux randomness). WebSocket relay transport: todo (interface milestones). |
| Portable backup import/export | P0 | green | `portable_backup.json` | format_version 1, seed-only and plaintext modes; TS imports the Python export, re-exports byte-identically under pinned nonce/timestamp, verifies canonical checksum, rejects tampering/unknown versions. |
| Entry creation (provision) | P0 | green | `entries_index.json` | TS `add*Entry` ops rebuild the Python `EntryManager` fixture index byte-for-byte (pinned clock): field shapes, id allocation, independent TOTP derivation-index allocation, ISO timestamp format. Not ported: index0 event emission, modify/archive ops. |
| Entry secret retrieval | P0 | green | `entry_secrets.json` | Reveal values match Python retrieval for password (v2), TOTP-at-time, nostr entry nsec (BIP-85 app 39 — NOT the sync client's 1237), seed and managed-account mnemonics. |
| CLI (Milestone 5, agent-blind MVP) | P1 | partial | — | `packages/cli` seedpass-js: capabilities, entry list/get/search (reference-first, `sp://entry/<id>`, secrets replaced by `has_*` flags), `entry add password/totp/key-value/document/seed/managed-account/nostr` (provision-blind: returns refs, never the created secret), `entry reveal` as the only plaintext egress, `use --clipboard/--exec/--stdin-to` sinks (env-var injection, never argv/stdout), vault export/import. Tests assert secrets never appear in default or provisioning output. Not yet: modify/archive, profiles, relay sync, leases/tokens. |

## Environment coverage

| Environment | Status |
|---|---|
| Node 22 (vitest) | green — 143/143 core + 16 CLI |
| jsdom browser-like env | green — 143/143 core |
| Real Chromium/Firefox (vitest browser mode) | todo — lands with Milestone 6 web app CI |

## Dependency notes (to expand into docs/typescript_dependency_review.md)

Crypto path uses the audited noble/scure family only: `@noble/hashes`,
`@noble/curves`, `@scure/bip32`, `@scure/bip39`, `@scure/base`. AES-GCM uses
platform WebCrypto (Node `crypto.subtle` / browser). No other runtime
dependencies in the core.

## Known intentional divergences

None yet. Any future divergence must carry a compatibility version, a
migration/fallback path, release notes, and tests (plan §6).
