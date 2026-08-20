/** Small byte/string helpers shared across the core. No Node or DOM APIs. */

import { sha256 } from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";

export function sha256Hex(data: Uint8Array): string {
  return bytesToHex(sha256(data));
}

export function hmacSha256Hex(key: Uint8Array, data: Uint8Array): string {
  return bytesToHex(hmac(sha256, key, data));
}

/**
 * Strip the characters Python's str.strip() treats as whitespace.
 *
 * JS trim() and Python strip() are not the same set: trim() removes U+FEFF
 * but leaves U+0085 and U+001C..U+001F, and Python does the reverse. That
 * difference changes derived keys and fingerprints between implementations.
 */
const PYTHON_WHITESPACE = "\t\n\v\f\r \u001c\u001d\u001e\u001f\u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000";

export function pythonStrip(value: string): string {
  let start = 0;
  let end = value.length;
  while (start < end && PYTHON_WHITESPACE.includes(value[start]!)) start++;
  while (end > start && PYTHON_WHITESPACE.includes(value[end - 1]!)) end--;
  return value.slice(start, end);
}

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function bytesToHex(b: Uint8Array): string {
  let out = "";
  for (const x of b) out += x.toString(16).padStart(2, "0");
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  // parseInt is prefix-lenient and sign-aware: "1z" parses as 1, "-1" as -1
  // (stored as 0xff). Relay-supplied ids and signatures reach this function,
  // so validate the whole string first, as Python's bytes.fromhex does.
  if (!/^[0-9a-fA-F]*$/.test(hex)) throw new Error("invalid hex");
  if (hex.length % 2 !== 0) throw new Error("odd-length hex");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Big-endian 32-bit unsigned counter, as Python's int.to_bytes(4, "big"). */
export function be32(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) {
    throw new Error(`be32 out of range: ${n}`);
  }
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

/** Interpret bytes as a big-endian bigint, as Python's int.from_bytes(b, "big"). */
export function bigintFromBytes(b: Uint8Array): bigint {
  let v = 0n;
  for (const x of b) v = (v << 8n) | BigInt(x);
  return v;
}

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}
