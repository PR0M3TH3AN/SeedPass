/**
 * Deterministic TOTP secret derivation and RFC 6238 code generation.
 *
 * Parity target: src/utils/key_derivation.py::derive_totp_secret and
 * src/seedpass/core/totp.py. Secret path uses purpose 39 with the constant
 * child 1414485072 (= 0x544F5450 = int.from_bytes(b"TOTP", "big")).
 */

import { hmac } from "@noble/hashes/hmac.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { sha1 } from "@noble/hashes/legacy.js";
import { base32 } from "@scure/base";
import { mnemonicToSeedSync } from "@scure/bip39";
import { HDKey } from "@scure/bip32";
import { utf8 } from "../util/bytes.js";

const TOTP_PURPOSE = 39;
const TOTP_INT = 0x544f5450; // 1414485072 = int.from_bytes(b"TOTP", "big")

/** Derive the base32 TOTP secret for an index from a mnemonic or raw seed. */
export function deriveTotpSecret(seed: string | Uint8Array, index: number): string {
  const seedBytes = typeof seed === "string" ? mnemonicToSeedSync(seed) : seed;
  const root = HDKey.fromMasterSeed(seedBytes);
  const path = `m/83696968'/${TOTP_PURPOSE}'/${TOTP_INT}'/${index}'`;
  const child = root.derive(path);
  if (!child.privateKey) throw new Error(`no private key at ${path}`);
  const entropy = hmac(sha512, utf8("bip-entropy-from-k"), child.privateKey);
  const hashed = sha256(entropy.slice(0, 32));
  return base32.encode(hashed.slice(0, 20));
}

/** RFC 4226 HOTP with SHA-1 (the TOTP default the Python side uses via pyotp). */
export function hotp(secretB32: string, counter: number, digits = 6): string {
  const key = base32.decode(secretB32);
  const msg = new Uint8Array(8);
  const view = new DataView(msg.buffer);
  view.setBigUint64(0, BigInt(counter), false);
  const digest = hmac(sha1, key, msg);
  const offset = digest[digest.length - 1]! & 0x0f;
  const code =
    (((digest[offset]! & 0x7f) << 24) |
      ((digest[offset + 1]! & 0xff) << 16) |
      ((digest[offset + 2]! & 0xff) << 8) |
      (digest[offset + 3]! & 0xff)) %
    10 ** digits;
  return code.toString().padStart(digits, "0");
}

/** RFC 6238 TOTP code at a unix timestamp. */
export function totpCodeAt(
  secretB32: string,
  timestamp: number,
  period = 30,
  digits = 6,
): string {
  return hotp(secretB32, Math.floor(timestamp / period), digits);
}
