/**
 * Numbers whose canonical form cannot be reproduced from a parsed JS value.
 *
 * Found by differential fuzzing against Python, not by reading the code — the
 * module's own comment previously asserted this ambiguity "does not arise".
 * It does, for data SeedPass did not write, which the port explicitly
 * supports carrying through.
 *
 * The detector runs on raw TEXT because that is the only moment the
 * distinction still exists: JSON.parse("0.0") and JSON.parse("0") produce the
 * same JS value.
 */

import { describe, expect, it } from "vitest";
import { findAmbiguousNumbers, canonicalJson } from "@seedpass/core";

describe("the limitation is real", () => {
  it("cannot tell an integral float from an integer once parsed", () => {
    // This is the whole problem in one assertion. Python emits "0.0" for the
    // first and "0" for the second; JS has one value for both.
    expect(JSON.parse("0.0")).toBe(JSON.parse("0"));
    expect(canonicalJson(JSON.parse("0.0"))).toBe("0");
  });

  it("refuses a value JSON.parse has already rounded", () => {
    // 10000000000000001 does not survive parsing, so any hash computed from
    // it would be a hash of the wrong number. Refusing is the safe direction.
    const rounded = JSON.parse("10000000000000001");
    expect(rounded).toBe(10000000000000000);
    expect(() => canonicalJson(rounded)).toThrow(/safe range/);
  });
});

describe("findAmbiguousNumbers", () => {
  it("flags integral floats", () => {
    expect(findAmbiguousNumbers('{"a":0.0}')).toEqual(["0.0"]);
    expect(findAmbiguousNumbers('{"a":-0.0}')).toEqual(["-0.0"]);
    expect(findAmbiguousNumbers('{"a":1.0,"b":2.00}')).toEqual(["1.0", "2.00"]);
    expect(findAmbiguousNumbers('{"a":2e3}')).toEqual(["2e3"]);
    expect(findAmbiguousNumbers('{"a":1e+16}')).toEqual(["1e+16"]);
  });

  it("flags values outside the safe-integer range", () => {
    expect(findAmbiguousNumbers('{"a":10000000000000001}')).toEqual(["10000000000000001"]);
  });

  it("stays quiet on everything SeedPass actually writes", () => {
    // Timestamps, lengths, counts, negative numbers and genuine fractions all
    // round-trip identically; flagging them would make the detector useless.
    const realistic = JSON.stringify({
      schema_version: 4,
      entries: {
        "0": { modified_ts: 1700000000, length: 16, index: 0, archived: false },
        "1": { period: 30, digits: 6, tags: ["a"], notes: "" },
      },
      _sync_meta: { next_index: 12, last_merge_ts: 1700000123 },
    });
    expect(findAmbiguousNumbers(realistic)).toEqual([]);
    expect(findAmbiguousNumbers('{"a":1.5,"b":-2.25,"c":1e-7}')).toEqual([]);
  });

  it("does not mistake digits inside strings for numbers", () => {
    // A label like "1.0" is text, not a number, and flagging it would train
    // the reader to ignore the warning.
    expect(findAmbiguousNumbers('{"label":"1.0","note":"0.0 and 1e+16"}')).toEqual([]);
    // Including when the string contains an escaped quote before the digits.
    expect(findAmbiguousNumbers('{"a":"say \\"1.0\\" now"}')).toEqual([]);
  });

  it("deduplicates and preserves first-appearance order", () => {
    expect(findAmbiguousNumbers('{"a":1.0,"b":0.0,"c":1.0}')).toEqual(["1.0", "0.0"]);
  });

  it("handles an empty or number-free document", () => {
    expect(findAmbiguousNumbers("{}")).toEqual([]);
    expect(findAmbiguousNumbers('{"a":"b"}')).toEqual([]);
    expect(findAmbiguousNumbers("")).toEqual([]);
  });
});
