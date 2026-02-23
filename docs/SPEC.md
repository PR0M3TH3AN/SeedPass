# SeedPass Specification

## Key Hierarchy

SeedPass derives a hierarchy of keys from a single BIP-39 parent seed using HKDF:

- **Master Key** – `HKDF(seed, "seedpass:v1:master")`
- **KEY_STORAGE** – used to encrypt vault data.
- **KEY_INDEX** – protects the metadata index.
- **KEY_PW_DERIVE** – deterministic password generation.
- **KEY_TOTP_DET** – deterministic TOTP secrets.

Each context string keeps derived keys domain separated.

## KDF Parameters

Passwords are protected with **PBKDF2-HMAC-SHA256**. The default work factor is
**50,000 iterations** but may be adjusted via the settings slider. The config
stores a `KdfConfig` structure with the chosen iteration count, algorithm name,
and the current spec version (`CURRENT_KDF_VERSION = 1`). Argon2 is available
with a default `time_cost` of 2 when selected.

## Message Formats

SeedPass synchronizes profiles over Nostr using three event kinds:

- **Manifest (`30070`)** – high level snapshot description and current version.
- **Snapshot Chunk (`30071`)** – compressed, encrypted portions of the vault.
- **Delta (`30072`)** – incremental changes since the last snapshot.

Events encode JSON and include tags for checksums, fingerprints, and timestamps.

## Versioning

Configuration and KDF schemas are versioned so clients can migrate older
profiles. Nostr events carry a version field in the manifest, and the software
follows semantic versioning for releases.

## Memory Protection

SeedPass encrypts sensitive values in memory and attempts to wipe them when no
longer needed. This zeroization is best-effort only; Python's memory management
may retain copies of decrypted data. Critical cryptographic operations may move
to a Rust/WASM module in the future to provide stronger guarantees.
