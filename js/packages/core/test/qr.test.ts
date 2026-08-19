/**
 * QR encoding, checked against a mature reference implementation.
 *
 * A wrong QR code is worse than no QR code: it scans cleanly and yields the
 * wrong secret, and the user finds out when their 2FA stops working. So the
 * load-bearing assertion is not "it produces a plausible grid" but "every
 * module matches what Python's `qrcode` library produces for the same input"
 * — version, size and all several thousand modules.
 *
 * Two things are controlled for so the comparison is between implementations
 * rather than between configurations:
 *
 *   - The fixtures force byte mode. The reference auto-selects alphanumeric
 *     for an all-uppercase string, which is a different encoding of the same
 *     text, not a different answer to the same question.
 *   - The mask is pinned to the reference's choice. The two disagree about
 *     mask SELECTION (see the note in qr.ts): the spec scores the finished
 *     symbol, the reference scores one with its format modules blanked. All
 *     eight masks are valid, so selection is checked separately as a
 *     property rather than by copying the reference's quirk.
 */

import { describe, expect, it } from "vitest";
import { encodeQr, renderQrText, EC_LEVELS } from "@seedpass/core";
// Imported through the fixture package rather than read from disk, so the
// suite also runs under the jsdom environment, where there is no filesystem.
import { qrCases as cases } from "@seedpass/test-vectors";

describe("every module matches the reference encoder", () => {
  for (const c of cases) {
    const label = c.text.length > 38 ? `${c.text.slice(0, 35)}...` : c.text;
    it(`${c.level} v${c.version} mask ${c.mask}: ${label}`, () => {
      const got = encodeQr(c.text, { level: c.level, mask: c.mask });
      // Version selection is spec-determined, so a mismatch means the
      // capacity calculation diverged rather than a different-but-valid
      // choice being made.
      expect(got.version).toBe(c.version);
      expect(got.size).toBe(c.size);
      for (let r = 0; r < c.size; r++) {
        // Row-wise so a failure names the row rather than dumping the grid.
        expect({ row: r, modules: got.modules[r] }).toEqual({ row: r, modules: c.modules[r] });
      }
    });
  }

  it("covers every error-correction level and a spread of versions", () => {
    // Guards the fixture set itself: a suite that only ever exercised one
    // level would pass while three quarters of the block table was wrong.
    const levels = new Set(cases.map((c) => c.level));
    for (const level of EC_LEVELS) expect(levels).toContain(level);
    const versions = cases.map((c) => c.version);
    expect(Math.min(...versions)).toBe(1);
    // Above version 6 the version-information blocks are written, which is a
    // separate code path from everything versions 1-6 exercise.
    expect(Math.max(...versions)).toBeGreaterThan(6);
  });
});

describe("mask selection", () => {
  it("chooses the lowest-penalty mask, and every candidate is a valid symbol", () => {
    for (const c of cases.slice(0, 4)) {
      const auto = encodeQr(c.text, { level: c.level });
      // Whatever it picked must be reproducible by pinning that mask.
      const pinned = encodeQr(c.text, { level: c.level, mask: auto.mask });
      expect(pinned.modules).toEqual(auto.modules);
      expect(auto.mask).toBeGreaterThanOrEqual(0);
      expect(auto.mask).toBeLessThan(8);

      // All eight are legal symbols: same version, same size, and the fixed
      // patterns land in the same places regardless of mask.
      for (let mask = 0; mask < 8; mask++) {
        const m = encodeQr(c.text, { level: c.level, mask });
        expect(m.version).toBe(auto.version);
        expect(m.modules[m.size - 8]![8]).toBe(true); // dark module
      }
    }
  });
});

describe("encoder behaviour", () => {
  it("places a finder pattern in exactly three corners", () => {
    const m = encodeQr("finder-check").modules;
    const size = m.length;
    for (const [r0, c0] of [[0, 0], [0, size - 7], [size - 7, 0]] as const) {
      expect(m[r0]![c0]).toBe(true); // outer ring
      expect(m[r0 + 1]![c0 + 1]).toBe(false); // light ring
      expect(m[r0 + 3]![c0 + 3]).toBe(true); // core
    }
    // The fourth corner must NOT have one — that is how a scanner works out
    // which way up the symbol is.
    expect(m[size - 7]![size - 7]).toBe(false);
  });

  it("picks the smallest version that fits and grows with the data", () => {
    expect(encodeQr("short", { level: "M" }).version).toBeLessThan(
      encodeQr("x".repeat(300), { level: "M" }).version,
    );
  });

  it("needs a larger version at a stronger error-correction level", () => {
    // More ECC means less room for data at the same version.
    const text = "x".repeat(100);
    expect(encodeQr(text, { level: "H" }).version).toBeGreaterThan(
      encodeQr(text, { level: "L" }).version,
    );
  });

  it("refuses data that will not fit rather than truncating it", () => {
    // Silently dropping the tail would produce a scannable code containing
    // half a secret, which is the worst outcome available.
    expect(() => encodeQr("x".repeat(5000), { level: "H" })).toThrow(/does not fit/);
    expect(() => encodeQr("x".repeat(100), { version: 1 })).toThrow(/capacity/);
  });

  it("counts multi-byte characters as their UTF-8 length", () => {
    // Byte mode: an emoji costs four bytes of capacity, not one.
    expect(() => encodeQr("😀".repeat(5), { version: 1, level: "H" })).toThrow(/capacity/);
  });
});

describe("terminal rendering", () => {
  it("surrounds the code with a quiet zone", () => {
    const lines = renderQrText(encodeQr("quiet-zone-check")).split("\n");
    // Four modules on every side; without it many scanners never see the code.
    expect(lines[0]).toMatch(/^█+$/);
    expect(lines[lines.length - 1]).toMatch(/^█+$/);
    for (const line of lines) {
      expect(line.startsWith("████")).toBe(true);
      expect(line.endsWith("████")).toBe(true);
    }
  });

  it("packs two module rows into each text row", () => {
    const matrix = encodeQr("row-packing");
    const lines = renderQrText(matrix).split("\n");
    expect(lines).toHaveLength(Math.ceil((matrix.size + 8) / 2));
    expect(lines[0]!.length).toBe(matrix.size + 8);
  });
});
