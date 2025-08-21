# SeedPass Specification

## Memory Protection

SeedPass encrypts sensitive values in memory and attempts to wipe them when no longer needed. This zeroization is best-effort only; Python's memory management may retain copies of decrypted data. Critical cryptographic operations may move to a Rust/WASM module in the future to provide stronger guarantees.

