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

/**
 * Numbers, formatted the way CPython's json module would.
 *
 * JS and Python disagree in several places, and every disagreement changes
 * an entry hash — which decides merge winners, so a mismatch means two
 * clients can diverge permanently. Handled here:
 *
 *   value                JS toString        CPython json
 *   1e16                 10000000000000000  1e+16
 *   1e-7                 1e-7               1e-07
 *   1e23                 1e+23              1e+23   (agrees)
 *   -0                   0                  -0.0
 *
 * Integral values are emitted without a decimal point, matching Python ints;
 * SeedPass data carries integers (timestamps, lengths, counts) and never
 * float-typed whole numbers, so the int/float ambiguity CPython would
 * otherwise expose does not arise. A non-integral or non-safe value would
 * be ambiguous, so it is rejected rather than guessed at.
 */
function encodeNumber(n: number): string {
  if (!Number.isFinite(n)) throw new Error("non-finite number in canonical JSON");
  if (Object.is(n, -0)) return "-0.0";
  if (Number.isInteger(n)) {
    if (!Number.isSafeInteger(n)) {
      throw new Error(
        `integer ${n} exceeds the safe range; its canonical form would differ ` +
          `from the Python reference and break hash agreement`,
      );
    }
    return n.toString();
  }
  return pythonFloatRepr(n);
}

/** CPython repr() for a float: shortest round-trip, two-digit exponent. */
function pythonFloatRepr(n: number): string {
  const s = n.toString();
  const m = /^(-?)(\d(?:\.\d+)?)e([+-])(\d+)$/.exec(s);
  if (m) {
    // JS writes 1e-7; CPython writes 1e-07 (exponent padded to two digits).
    const [, sign, mantissa, expSign, expDigits] = m;
    return `${sign}${mantissa}e${expSign}${expDigits!.padStart(2, "0")}`;
  }
  if (Math.abs(n) >= 1e16) {
    // CPython switches to exponent form at 1e16; JS does so only at 1e21.
    const exp = n.toExponential();
    const em = /^(-?\d(?:\.\d+)?)e([+-])(\d+)$/.exec(exp)!;
    return `${em[1]}e${em[2]}${em[3]!.padStart(2, "0")}`;
  }
  return s;
}

/** Code-point ordering, matching Python's sorted() on str. */
export function compareCodePoints(a: string, b: string): number {
  const ai = Array.from(a);
  const bi = Array.from(b);
  const len = Math.min(ai.length, bi.length);
  for (let i = 0; i < len; i++) {
    const d = ai[i]!.codePointAt(0)! - bi[i]!.codePointAt(0)!;
    if (d !== 0) return d;
  }
  return ai.length - bi.length;
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
      // Python sorts by code point; JS's default sort compares UTF-16 code
      // units, which disagree once a supplementary-plane key (an emoji in a
      // tag, say) sits alongside one at or above U+E000.
      const keys = Object.keys(value as Record<string, unknown>).sort(compareCodePoints);
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
