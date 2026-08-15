/**
 * Vault index key derivation (seed-only mode, v1 hierarchy).
 *
 * Parity target: src/utils/key_derivation.py::derive_index_key_seed_only and
 * src/utils/key_hierarchy.py::kd. HKDF-SHA256 with no salt (RFC 5869 zero
 * salt) and domain-separation info strings.
 */

import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { base64url } from "@scure/base";
import { mnemonicToSeedSync } from "@scure/bip39";
import { utf8 } from "../util/bytes.js";
import { canonicalizeMnemonic } from "../derive/bip85.js";

function kd(root: Uint8Array, info: Uint8Array, length = 32): Uint8Array {
  return hkdf(sha256, root, undefined, info, length);
}

/** Raw 32-byte index encryption key. */
export function deriveIndexKeyBytes(mnemonic: string): Uint8Array {
  // Canonicalize first: deriving from a raw string that merely passed a
  // word-count check yields a key nothing else can reproduce.
  const seed = mnemonicToSeedSync(canonicalizeMnemonic(mnemonic));
  const master = kd(seed, utf8("seedpass:v1:master"));
  return kd(master, utf8("seedpass:v1:storage"));
}

/** URL-safe base64 form, as the Python side stores it (Fernet-compatible). */
export function deriveIndexKey(mnemonic: string): string {
  return base64url.encode(deriveIndexKeyBytes(mnemonic));
}
