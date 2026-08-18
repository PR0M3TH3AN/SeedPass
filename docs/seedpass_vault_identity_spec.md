# SeedPass Vault & Identity Specification — v1 (draft)

Status: **draft, extracted from working code** — 2026-08-18
Reference implementations: Python (`src/seedpass/`), TypeScript (`js/packages/core/`)
Conformance oracle: `scripts/cross_impl_check.py` (36 checks) + `js/packages/test-vectors/`

## 1. Purpose and scope

One deterministic account tree, multiple management interfaces. This document
specifies the on-disk formats, derivation rules, and interoperability
requirements that let independent applications operate the **same** vault —
SeedPass as the sovereign superset (root management, recovery, all secret
kinds), and narrower clients such as BitLogin (identity and managed-account
administration) implementing a subset.

The core promise this spec exists to protect:

> **An entry index is a permanent cryptographic coordinate.** "Alice is
> managed account #184" must deterministically identify the same derived
> identity for the life of the root — across implementations, devices, and
> decades.

Everything here is **extracted from code that ships and is cross-verified**,
not aspiration. Where an implementation falls short of a requirement, that is
listed in §12 rather than papered over.

Out of scope, deliberately: authentication protocols, signing services,
policy/authorization engines, organizations, payments, workflows. Those are
application features. They store their data *in* this format (§8) but are not
part of it. A format that absorbed them would make every implementation carry
every application's complexity.

## 2. Terminology

| Term | Meaning |
|---|---|
| **Parent seed** | A BIP-39 mnemonic (12/18/24 English words). The root of everything. |
| **Profile / fingerprint** | One parent seed's vault. Identified by its fingerprint (§3.2). |
| **Entry** | One record in the vault index, keyed by its **entry id**. |
| **Entry id / index** | Decimal-string key of an entry; doubles as the derivation index for derived kinds (§6). Never reused (§7). |
| **Managed account** | A `managed_account` entry: a child BIP-39 seed derived at the entry id, with its own fingerprint — a delegable sub-identity. |
| **Implementation** | Any software reading/writing this format. |

Normative words **MUST / MUST NOT / SHOULD / MAY** are used in the RFC-2119
sense.

## 3. Canonicalization and identity

### 3.1 Canonical mnemonic form

Before **any** validation, derivation, or fingerprinting, a mnemonic MUST be
canonicalized:

```
NFKD → trim → lowercase → collapse internal whitespace to single spaces
```

Deriving from a non-canonical string that merely passed a word-count check
produces a vault no other implementation (or the user's written-down phrase)
can reopen. Implementations MUST reject mnemonics that fail BIP-39 checksum
validation after canonicalization — BIP-39 seed derivation itself accepts any
string, so a typo silently creates an unrecoverable vault.

### 3.2 Profile fingerprint

```
fingerprint = uppercase( hex( SHA-256( utf8(canonical_mnemonic) ) )[0:16] )
```

16 uppercase hex characters. Identifies the profile directory and appears in
`managed_account.fingerprint` for child seeds.

### 3.3 Master password normalization

Password-derived keys (§4.2) normalize the password as `NFKD` then strip
Python's `str.strip()` whitespace set (which differs from JS `trim()`; the
Python set is normative).

## 4. Container formats

### 4.1 Vault index file (`seedpass_entries_db.json.enc`)

Stored as either a bare ciphertext or a JSON wrapper
`{"kdf": {...}, "ct": "<base64>"}`. The plaintext is the vault index (§5)
as UTF-8 JSON.

Payload formats, by prefix:

| Prefix | Format | Write? |
|---|---|---|
| `V3\|` | 12-byte nonce ‖ AES-256-GCM ciphertext‖tag | **current — all writes** |
| `V2:` | same construction, legacy prefix (with Fernet fallback on auth failure) | read-only |
| (none) | legacy Fernet token | read-only |

Key: the **index key** (see `docs/SPEC.md` key hierarchy):

```
seed   = BIP39-seed(canonical_mnemonic)          # no passphrase
master = HKDF-SHA256(seed,   salt=∅, info="seedpass:v1:master",  32)
key    = HKDF-SHA256(master, salt=∅, info="seedpass:v1:storage", 32)
```

The index key derives from the **seed, not the password** — changing the
master password re-wraps only the parent seed file.

### 4.2 Parent seed file (`parent_seed.enc`)

JSON wrapper `{"kdf", "ct"}`; `ct` is a V3 payload of the canonical mnemonic
under a password-derived key:

```
salt = SHA-256(fingerprint)[0:16]
key  = PBKDF2-HMAC-SHA256(normalized_password, salt, iterations, 32)   # default 200 000
```

`kdf` records `{name: "pbkdf2", version: 1, params: {iterations}, salt_b64}`.
Argon2id (`name: "argon2id"`, params `time_cost`/`memory_cost`/`parallelism`)
is also valid. Implementations MUST bound KDF parameters read from disk
before running them (the block sits outside the AEAD; unbounded values are a
denial-of-service).

### 4.3 Per-profile config (`seedpass_config.json.enc`)

Same encryption as the index, same key. Free-form JSON object;
implementations MUST preserve keys they do not understand.

## 5. The vault index

```jsonc
{
  "schema_version": 4,
  "entries": { "<id>": { /* entry record, §5.2 */ } },
  "_sync_meta": {                  // sync + allocation metadata (§7, §9)
    "strategy": "modified_ts_hash_tombstone_v2",
    "last_merge_ts": 0,
    "next_index": 0,               // allocation watermark, §7
    "tombstones": { "<id>": { "deleted_ts", "entry_hash", "event_hash", "source" } },
    "sources": [], "source_count": 0
  },
  "_system": { "index0": { /* derived state; not part of this spec */ } }
}
```

- `schema_version` is currently **4**. An implementation MUST refuse to open
  a version above what it supports (a newer writer may have written fields it
  would destroy) and MUST migrate older versions forward before writing.
- Entry ids are decimal strings matching `^(0|[1-9][0-9]*)$`, within
  JavaScript's safe-integer range. Both constraints are normative: they are
  what makes the two reference implementations compute identical allocation
  floors from one payload (Unicode digits and leading zeros are rejected, not
  interpreted).

### 5.2 Entry records

Every entry carries the base fields:

```
type, kind        # equal strings; `kind` may be absent in pre-v2 data (fall back to `type`)
label             # human name
archived          # boolean (legacy alias: `blacklisted`)
date_added, date_modified   # ISO-8601
modified_ts       # unix seconds; drives sync conflict resolution
notes             # string
tags              # array of strings (freeform; `team:design` style encouraged)
links             # array (entry relationships)
custom_fields     # [{label, value, is_hidden?}]
origin            # optional provenance marker
```

Kind-specific fields (schema v4):

| kind | fields | secret material |
|---|---|---|
| `password` | `length` (8–128), `gen_version` (absent ⇒ 1), `username?`, `url?` | derived (§6) |
| `totp` | `deterministic?`, `period` (30), `digits` (6), `index?` **or** `secret?` | derived or stored |
| `ssh` | `index` | derived |
| `seed` | `index`, `word_count` ∈ {12,18,24} | derived |
| `pgp` | `index`, `key_type` ("ed25519"), `user_id` | derived |
| `nostr` | `index` | derived |
| `key_value` | `key`, `value` | stored |
| `managed_account` | `index`, `word_count`, `fingerprint` (child's, §3.2) | derived |
| `document` | `content`, `file_type` | stored |

**Redaction rule:** listing/metadata surfaces MUST NOT emit stored secret
fields (`value`, `secret`, `content`, hidden custom fields); they are
reported as `has_*` booleans. Plaintext appears only through operations whose
stated purpose is producing it.

## 6. Deterministic derivation

All derived secrets come from BIP-85 over the canonical parent seed
(BIP-32/SLIP-10 secp256k1 master; entropy =
`HMAC-SHA512(key="bip-entropy-from-k", child_private_key)`).

| What | Path | Entropy → secret |
|---|---|---|
| Child mnemonic (`seed`, `managed_account`) | `m/83696968'/39'/0'/{word_count}'/{id}'` | 16/24/32 bytes → BIP-39 words |
| Password (`password`) | `m/83696968'/32'/{id}'` | 64 bytes → generator v1/v2 (`gen_version`) |
| SSH key (`ssh`) | `m/83696968'/32'/{index}'` | 32 bytes → Ed25519 |
| PGP key (`pgp`) | `m/83696968'/32'/{index}'` | 32 bytes → Ed25519 (RSA is not reproducible; refuse) |
| Nostr **entry** key (`nostr`) | `m/83696968'/39'/0'/32'/{index}'` | 32 bytes → secp256k1 nsec |
| Deterministic TOTP | `m/83696968'/39'/1414485072'/{totp_index}'` | SHA-256(entropy[0:32])[0:20] → base32 |
| Nostr **sync identity** | `m/83696968'/1237'/{account}'` (default account 0) | 32 bytes → the profile's relay identity |

Notes with teeth:

- **Password generation v1 is frozen.** A fix that would change v1 output
  goes into a new `gen_version`, never into v1. 18 frozen vectors enforce
  this; a failure there is never "update the expected value".
- **The Nostr entry-key path is the app-39 path with `word_count=32`** — a
  historical quirk, now load-bearing. Do not "correct" it.
- `ssh` and `pgp` share app 32 with passwords — a known, shared-with-Python
  namespace collision. Changing it requires a coordinated versioned change
  in every implementation (§13); until then it is the standard.

### 6.1 The two index namespaces

- For `password`, `seed`, `managed_account`, and `nostr` entries, **the
  derivation index IS the entry id.**
- **Deterministic TOTP has its own namespace**: `totp.index` is allocated as
  max over existing totp entries' `index` + 1, independent of entry ids.

When a human says "account #N", that N is an **entry id**. Applications
presenting managed accounts MUST display the entry id and SHOULD label it
exactly "Account #N" so the recovery coordinate users memorize is the one
that regenerates the identity.

## 7. Index allocation — the immutability rule

**An id, once allocated, is never reallocated** — not after deletion, not
after archive, not after sync. Reissuing a deleted #184 would hand a new
entry the departed identity's exact derived secrets.

Normative mechanism (implemented in both references, 2026-08-18):

```
floor(index) = max( _sync_meta.next_index        # persisted watermark, default 0
                  , max(live entry ids) + 1
                  , max(tombstoned ids)  + 1 )   # tombstones still in retention
```

- Allocation MUST return `floor`.
- Every insert (including at an explicitly chosen id) and every index save
  MUST raise the watermark to at least `id + 1` / `floor`. The watermark
  never decreases.
- Merge (§9) MUST set `next_index = max(both sides' watermarks,
  max(merged entry ids)+1, max(merged tombstone ids)+1)` — byte-identical
  across implementations.
- Deletion of derived-kind entries SHOULD be discouraged in UIs in favor of
  `archived: true`; archive preserves the record, and the watermark protects
  the coordinate even when deletion happens anyway.

The watermark lives in `_sync_meta` because every implementation already
round-trips that block (it carries the tombstones), so pre-watermark builds
preserve it without a schema bump. Pre-watermark vaults heal on their next
allocation via the tombstone term, and permanently once any save persists
the watermark.

## 8. Interoperability rules for multiple applications

These are what let SeedPass and a narrower client (BitLogin) share one vault
without requiring each other.

1. **Preservation.** An implementation MUST preserve fields it does not
   understand — on entries, on the index top level, and in config — across a
   read-modify-write cycle. (Both references hold this for *fields* today;
   see §12 for the unknown-*kind* gap.)
2. **Unknown kinds.** An implementation encountering an entry `kind` it does
   not understand MUST either (a) carry it through untouched, or (b) refuse
   to write the vault. Silently dropping it is forbidden. (a) is strongly
   preferred; (b) is the fail-closed floor.
3. **Namespacing.** Application-specific metadata goes in namespaced fields
   on existing records (e.g. `bitlogin: { permissions: {...} }`) or in new
   record kinds with a namespaced prefix (e.g. `kind: "bitlogin_org"`). Core
   fields (§5.2) MUST NOT be repurposed.
4. **No shadow identity.** A subset client MUST NOT maintain its own mapping
   of "its" account numbers to derivation indexes. The entry id is the only
   account number. (This is the "no translation table" rule.)
5. **Subset writing.** A client MAY understand only some kinds (BitLogin:
   `managed_account`, `nostr`, its own namespaced kinds). It MUST NOT create
   entries of kinds it cannot correctly derive or validate.
6. **Round-trip conformance.** For any vault V and conforming
   implementations A and B: `open(A, save(A, V))` and interleaved
   `save(B, open(B, save(A, V)))` MUST preserve all records, ids, and
   unknown fields. This is mechanically checkable and SHOULD be in CI for
   every new implementation (the Python↔TypeScript harness is the template).

### 8.1 Capability declaration

An implementation SHOULD be able to state its profile:

```json
{
  "application": "bitlogin",
  "spec_version": 1,
  "capabilities": ["core", "identity.nostr", "identity.managed_accounts", "tags"],
  "kinds": ["nostr", "managed_account", "bitlogin_org"]
}
```

Capability groups: **core** (container, index, allocation, preservation) —
mandatory; **identity** (nostr keys, managed accounts); **secrets**
(passwords, TOTP, SSH, PGP, key-value, documents); **advanced** (nested
roots, portable backup, sync). SeedPass implements all four; an identity
client needs only core + identity.

## 9. Synchronization (Nostr)

Profile identity: BIP-85 app 1237 (§6). Events (NIP-01, BIP-340 signed):

| kind | content |
|---|---|
| 30070 | manifest |
| 30071 | snapshot chunk (encrypted, gzip'd, chunked) |
| 30072 | delta (encrypted) |

Merge strategy `modified_ts_hash_tombstone_v2`: higher `modified_ts` wins;
equal timestamps break ties by canonical hash with field-level union;
deletions propagate as tombstones which beat older entries and lose to newer
ones; tombstone-vs-tombstone prefers newer `deleted_ts` then higher event
hash. Tombstone retention is capped at **2048** (oldest evicted first) —
which is why the allocation watermark (§7), not tombstone memory, carries
the never-reuse guarantee. Merged `_sync_meta` fields (`last_merge_ts`,
`next_index`, `sources`, `tombstones`) MUST be computed identically by every
implementation: convergence is defined as byte-identical canonical state.

Payload bodies are encrypted with keys derived from the parent seed; relays
hold ciphertext only. Applications MUST NOT publish plaintext business or
personal data in event content or tags.

## 10. Portable backup

`format_version: 1`. Encrypted-by-default export (`cipher`, `checksum` =
SHA-256 over canonical inner payload), decryptable from the parent seed
alone ("seed-only"). Both references import/export it; Python verifies
TS-written checksums in CI and vice versa.

## 11. Managed accounts for identity clients (informative)

The intended BitLogin-style flow, stated in this spec's terms:

- The **management root** is a SeedPass parent seed (possibly itself a
  `seed`/`managed_account` child of a personal root — delegate a subtree,
  never the main root).
- Creating "Alice" = creating a `managed_account` entry. Its **entry id** is
  her permanent account number; her child seed derives per §6; her Nostr
  identity derives from that child seed.
- The client provisions the *child* key into its online signer at creation
  time; the root returns to cold storage. Signing availability never
  requires the root online.
- Recovery: root + entry id regenerates the identity from nothing. This is
  why §7 is absolute.
- Roles, credentials, policies, org structure: the client's own data, stored
  under §8.3 namespacing. Not this spec.

## 12. Known conformance gaps (honest ledger)

| Gap | Where | Consequence | Status |
|---|---|---|---|
| Unknown entry `kind` fails the whole index parse (fail-closed, option (b) of §8.2, where (a) is preferred) | TypeScript `entryUnionSchema` | A vault containing a future kind can't be opened by current TS builds | open — needs an opaque-record passthrough |
| `_system.index0` merge handles only the empty case | both | non-empty index0 refuses to merge (loudly) | by design until atlas milestone |
| `ssh`/`pgp`/`password` share BIP-85 app 32 | both (spec-level) | namespace collision, shared with Python since v1 | frozen; change requires coordinated version bump |
| RSA PGP not derivable | TypeScript | refuses rather than diverging | permanent (RSA generation is not reproducible) |

## 13. Change control

- Any change to derivation output, container format, allocation, or merge
  semantics is a **versioned change**: it lands in every reference
  implementation in lockstep, behind a version field, with cross-impl tests
  proving old data still reads. The frozen-v1 password rule generalizes:
  **never alter the output of a version that exists in the wild.**
- Fixtures under `js/packages/test-vectors/fixtures/` are generated by the
  Python reference (`scripts/generate_ts_port_fixtures.py`) and are the
  ground truth a new implementation tests against.
- This document is descriptive of the code; where they disagree, the code +
  cross-impl suite win, and the document gets fixed.
