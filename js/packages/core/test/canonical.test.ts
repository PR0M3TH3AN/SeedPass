/**
 * canonicalJson must agree with CPython's json.dumps byte-for-byte.
 *
 * Entry and tombstone hashes are computed over this output and decide merge
 * winners, so any disagreement lets two clients keep different versions of
 * the same entry and never converge. A security review found real
 * divergences here (exponent padding, code-unit vs code-point key order)
 * that the older fixtures missed by only ever using ASCII keys and integers.
 */

import { describe, expect, it } from "vitest";
import { canonicalJsonCases, canonicalJsonUnsupported } from "@seedpass/test-vectors";
import { canonicalJson, canonicalHash } from "@seedpass/core";

describe("canonical JSON parity with Python", () => {
  it.each(canonicalJsonCases.map((c, i) => ({ ...c, i })))(
    "case $i matches json.dumps",
    ({ value, canonical }) => {
      expect(canonicalJson(value)).toBe(canonical);
    },
  );

  it("orders keys by code point, not UTF-16 code unit", () => {
    // U+FF01 sorts before U+1F600 by code point; the default JS sort, which
    // compares code units, puts the surrogate pair first.
    const out = canonicalJson({ "\u{1F600}": 1, "！": 2 });
    expect(out.indexOf("uff01")).toBeLessThan(out.indexOf("ud83d"));
  });

  it("refuses values whose canonical form would be ambiguous", () => {
    // Above 2**53 JSON cannot distinguish a Python int from a float, so the
    // two implementations cannot be made to agree; refuse rather than guess.
    expect(() => canonicalJson({ n: Number.MAX_SAFE_INTEGER + 2 })).toThrow(/safe range/);
    expect(() => canonicalJson({ n: Infinity })).toThrow(/non-finite/);
    for (const value of canonicalJsonUnsupported) {
      expect(() => canonicalJson(value)).toThrow();
    }
  });

  it("hashes are stable for the same logical value", () => {
    expect(canonicalHash({ a: 1, b: 2 })).toBe(canonicalHash({ b: 2, a: 1 }));
  });
});
