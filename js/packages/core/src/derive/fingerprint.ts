/**
 * Profile fingerprint: SHA256(mnemonic.strip().lower()) hex, first 16
 * characters, uppercased. Parity target: src/utils/fingerprint.py.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8 } from "../util/bytes.js";
import { canonicalizeMnemonic } from "./bip85.js";

export function generateFingerprint(seedPhrase: string, length = 16): string {
  // Same canonical form as derivation, so the fingerprint identifies the
  // vault the seed actually opens.
  const normalized = canonicalizeMnemonic(seedPhrase);
  const digest = sha256(utf8(normalized));
  return bytesToHex(digest).slice(0, length).toUpperCase();
}
