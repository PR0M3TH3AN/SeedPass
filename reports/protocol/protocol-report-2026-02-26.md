# Protocol Compliance Report - 2026-02-26

**Agent:** `protocol-research-agent`
**Focus:** Protocol Inventory & Compliance Assessment

## Executive Summary
The codebase relies heavily on standard libraries (`cryptography`, `bip-utils`, `nostr-sdk`, `pyotp`) for cryptographic and protocol implementations, ensuring a high baseline of compliance. Most protocol implementations delegate to these libraries directly.

One potential deviation from standard specifications was identified in the local BIP85 implementation regarding the application number used for symmetric key derivation.

## Findings

### 1. Strong Library Usage
- **BIP39/32**: `bip-utils` is used consistently.
- **Crypto**: `cryptography` (hazmat) is used for AES-GCM, HKDF, and Ed25519.
- **Nostr**: `nostr-sdk` (Rust bindings) handles protocol complexity.

### 2. BIP85 Custom Derivation Path
The implementation in `src/local_bip85/bip85.py` uses `app_no=2` for symmetric key derivation:
```python
def derive_symmetric_key(self, index: int = 0, app_no: int = 2) -> bytes:
```
According to [BIP-85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki), `app_no` mappings are:
- `0`: BIP32
- `2`: WIF (Wallet Import Format) - *Wait, spec usually assigns 2 to WIF.*
- `128`: Hex

However, the implementation derives raw entropy bytes for a symmetric key using `app_no=2`. If this is intended to match WIF generation logic, it might be acceptable, but typically symmetric keys (Hex) use `app_no=128`.
**Risk:** Low (internal consistency is maintained), but interoperability with other BIP85 wallets for this specific derivation might be limited.

### 3. BIP39 Word Count Default
The `derive_entropy` method defaults `word_count` to `entropy_bytes` if `word_count` is None for `app_no=39`.
```python
if app_no == 39:
    if word_count is None:
        word_count = entropy_bytes
```
This is safe as long as `derive_mnemonic` (the primary caller) passes explicit `words_num`. Direct calls to `derive_entropy` with `app_no=39` and `word_count=None` could result in non-standard derivation paths (e.g., `.../16'/...` for 16 bytes entropy).

## Recommendations
1. **Document `app_no=2` usage**: Clarify in comments why `2` is used for symmetric keys (legacy or specific compatibility).
2. **Add Compliance Tests**: Verify `derive_entropy` produces expected output vectors (if available) or at least remains stable.
3. **Monitor `nostr-sdk` updates**: Ensure the Rust bindings stay updated to support newer NIPs.

## Next Steps
- Add regression test for `app_no=2` derivation path to prevent accidental changes.
- Investigate if `app_no=128` (Hex) was the intended target for symmetric keys.
