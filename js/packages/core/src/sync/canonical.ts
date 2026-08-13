/**
 * Python-compatible canonical JSON:
 *   json.dumps(value, sort_keys=True, separators=(",", ":"))
 *
 * Entry and tombstone hashes are SHA-256 over this exact byte sequence, so
 * key ordering, ASCII escaping (Python defaults to ensure_ascii=True) and
 * number formatting must match Python byte-for-byte for hash parity.
 * Values here are JSON-shaped data (from JSON.parse or fixtures), so
 * non-finite numbers and non-plain objects are rejected loudly.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8 } from "../util/bytes.js";

const ESCAPES: Record<string, string> = {
  '"': '\\"',
  "\\": "\\\\",
  "\b": "\\b",
  "\f": "\\f",
  "\n": "\\n",
  "\r": "\\r",
  "\t": "\\t",
};

function encodeString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]!;
    const code = s.charCodeAt(i);
    const mapped = ESCAPES[ch];
    if (mapped !== undefined) {
      out += mapped;
    } else if (code < 0x20 || code > 0x7e) {
      // ensure_ascii: everything outside printable ASCII becomes \uXXXX
      // (surrogate pairs escape as two code units, same as CPython)
      out += "\\u" + code.toString(16).padStart(4, "0");
    } else {
      out += ch;
    }
  }
  return out + '"';
}

function encodeNumber(n: number): string {
  if (!Number.isFinite(n)) throw new Error("non-finite number in canonical JSON");
  if (Number.isInteger(n) && Object.is(n, -0) === false) return n.toString();
  // Python repr(float) and JS toString agree on shortest-roundtrip decimals
  // for doubles; integral floats (1.0) cannot be distinguished from ints in
  // JSON-parsed data, so both sides serialize them identically.
  return n.toString();
}

export function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      return encodeNumber(value);
    case "string":
      return encodeString(value);
    case "object": {
      if (Array.isArray(value)) {
        return "[" + value.map(canonicalJson).join(",") + "]";
      }
      const proto = Object.getPrototypeOf(value);
      if (proto !== Object.prototype && proto !== null) {
        throw new Error("non-plain object in canonical JSON");
      }
      const keys = Object.keys(value as Record<string, unknown>).sort();
      const parts = keys.map(
        (k) => encodeString(k) + ":" + canonicalJson((value as Record<string, unknown>)[k]),
      );
      return "{" + parts.join(",") + "}";
    }
    default:
      throw new Error(`unsupported type in canonical JSON: ${typeof value}`);
  }
}

export function canonicalHash(value: unknown): string {
  return bytesToHex(sha256(utf8(canonicalJson(value))));
}
