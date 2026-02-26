# Protocol Inventory

| Protocol | Source | Implementation | Status | Notes |
|----------|--------|----------------|--------|-------|
| **BIP39** | [bips/bip-0039](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) | `src/local_bip85/bip85.py`<br>`src/seedpass/core/seedqr.py` | **Compliant** | Uses `bip-utils` for standard mnemonic generation. |
| **BIP32** | [bips/bip-0032](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) | `src/local_bip85/bip85.py` | **Compliant** | Uses `bip-utils` (`Bip32Slip10Secp256k1`) for HD key derivation. |
| **BIP85** | [bips/bip-0085](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki) | `src/local_bip85/bip85.py` | **Partial** | Implements BIP39 derivation correctly (`app_no=39`).<br>Generic entropy (`app_no=2`) usage needs verification against spec (Hex app is usually 128'). |
| **SLIP-0010** | [satoshilabs/slips/slip-0010](https://github.com/satoshilabs/slips/blob/master/slip-0010.md) | `src/local_bip85/bip85.py` | **Compliant** | Used via `bip-utils` for Secp256k1 derivation. |
| **Nostr** | [nostr-protocol/nips](https://github.com/nostr-protocol/nips) | `src/nostr/client.py`<br>`src/nostr/key_manager.py` | **Compliant** | Uses `nostr-sdk` (Rust bindings) for protocol operations. |
| **HKDF** | [RFC 5869](https://tools.ietf.org/html/rfc5869) | `src/utils/key_derivation.py`<br>`src/local_bip85/bip85.py` | **Compliant** | Uses `cryptography` library implementation. |
| **AES-GCM** | [NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final) | `src/utils/memory_protection.py`<br>`src/seedpass/core/encryption.py` | **Compliant** | Uses `cryptography` library. Ensure nonces are unique (random). |
| **TOTP** | [RFC 6238](https://tools.ietf.org/html/rfc6238) | `src/seedpass/core/totp.py`<br>`src/utils/key_validation.py` | **Compliant** | Uses `pyotp`. |
| **OpenPGP** | [RFC 4880](https://tools.ietf.org/html/rfc4880) | `src/utils/key_validation.py`<br>`src/seedpass/core/password_generation.py` | **Compliant** | Uses `pgpy`. |
| **Bech32** | [bips/bip-0173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki) | `src/nostr/client.py` (implied) | **Compliant** | Uses `bech32` library. |

## Gap Analysis
- **BIP85 `app_no=2`**: The implementation uses `app_no=2` for symmetric key derivation. BIP85 spec assigns `2` to nothing? `0` is BIP32, `2` is usually WIF (in some implementations) or unassigned. Hex/Raw entropy is usually `128'`. This custom derivation path should be documented or aligned if interoperability is desired.
- **Nostr Relay Health**: No explicit relay health check protocol (NIP-11) found in `src/nostr/`, but `nostr-sdk` handles much of this.
