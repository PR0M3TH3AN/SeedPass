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
 * TWO KNOWN LIMITATIONS, both found by differential fuzzing against Python
 * (scripts/differential_fuzz.py) rather than by reading:
 *
 * 1. INTEGRAL FLOATS CANNOT BE REPRODUCED. Python distinguishes int from
 *    float; JavaScript does not. `JSON.parse("0.0")` and `JSON.parse("0")`
 *    yield the same JS value, so this function emits "0" where CPython emits
 *    "0.0". No amount of formatting fixes it — the information is destroyed
 *    at parse time.
 *
 *    Data SeedPass writes is unaffected: timestamps, lengths and counts are
 *    Python ints and JS integers on both sides. It bites on data SeedPass did
 *    not write — an unknown-kind record carried through verbatim, a
 *    hand-edited vault, a third-party tool — which the port explicitly
 *    supports carrying. The consequence is a different entry hash, and entry
 *    hashes break same-timestamp merge ties, so two clients could converge to
 *    different vaults. Use `findAmbiguousNumbers` on the raw JSON text to
 *    detect it while the distinction still exists.
 *
 * 2. VALUES OUTSIDE THE SAFE-INTEGER RANGE ARE REFUSED, where Python encodes
 *    them. That is deliberate and is the safe direction: `JSON.parse` has
 *    already rounded such a value (10000000000000001 becomes
 *    10000000000000000), so the number in hand is not the number on disk and
 *    any hash computed from it would be wrong. Refusing loudly beats hashing
 *    a corrupted value.
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

/**
 * Number literals in `jsonText` whose canonical form this module cannot
 * reproduce byte-for-byte.
 *
 * Must be run on the raw JSON TEXT, before `JSON.parse`: the whole problem is
 * that parsing destroys the int/float distinction Python preserves. Returns
 * the offending literals (deduplicated, in order of first appearance), or an
 * empty array when the text is safe.
 *
 * Reports two classes, matching the limitations documented above:
 *   - integral floats: `0.0`, `-0.0`, `1.0`, `2e3` — Python writes a decimal
 *     point or exponent, this module cannot know to.
 *   - out-of-safe-range values: already rounded by the time JS sees them.
 *
 * Non-integral floats like `1.5` are NOT reported: those survive parsing and
 * are encoded to match CPython by `pythonFloatRepr`.
 */
export function findAmbiguousNumbers(jsonText: string): string[] {
  const found: string[] = [];
  const seen = new Set<string>();
  // JSON number grammar, anchored so it cannot match digits inside a string.
  // Strings are skipped explicitly rather than by lookaround, because an
  // escaped quote inside a string would defeat a naive pattern.
  let inString = false;
  let escaped = false;
  for (let i = 0; i < jsonText.length; i++) {
    const ch = jsonText[i]!;
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') {
      inString = true;
      continue;
    }
    if (ch !== "-" && (ch < "0" || ch > "9")) continue;
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(jsonText.slice(i));
    if (!match) continue;
    const literal = match[0];
    i += literal.length - 1;

    const value = Number(literal);
    const hasFractionOrExponent = /[.eE]/.test(literal);
    const ambiguous =
      // An integral value written as a float: Python keeps the decimal point.
      (hasFractionOrExponent && Number.isInteger(value)) ||
      // Already rounded by JSON.parse; the value in hand is not the one on disk.
      (Number.isInteger(value) && !Number.isSafeInteger(value));
    if (ambiguous && !seen.has(literal)) {
      seen.add(literal);
      found.push(literal);
    }
  }
  return found;
}
