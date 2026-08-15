/**
 * Interactive-mode input decoding and layout helpers.
 *
 * The screens themselves are exercised through a real pty in
 * `test/tui-pty.test.ts`; this file covers the pure logic, where the
 * interesting failures are silent: a dropped keypress, or a width
 * calculation that counts escape bytes as visible characters and wraps every
 * highlighted row.
 */

import { describe, expect, it } from "vitest";
import { decodeKeys, visibleLength, ansi, ESC } from "../src/tui/terminal.js";

describe("decodeKeys", () => {
  it("decodes printable characters", () => {
    expect(decodeKeys("abc")).toEqual([
      { name: "char", ch: "a" },
      { name: "char", ch: "b" },
      { name: "char", ch: "c" },
    ]);
  });

  it("decodes arrow keys in both cursor modes", () => {
    // Terminals send SS3 (ESC O A) in application cursor mode and CSI
    // (ESC [ A) otherwise; handling only one leaves arrows dead in some
    // terminals and not others.
    expect(decodeKeys(`${ESC}[A`)[0]!.name).toBe("up");
    expect(decodeKeys(`${ESC}OA`)[0]!.name).toBe("up");
    expect(decodeKeys(`${ESC}[B`)[0]!.name).toBe("down");
    expect(decodeKeys(`${ESC}[D`)[0]!.name).toBe("left");
  });

  it("decodes navigation and editing keys", () => {
    expect(decodeKeys("\r")[0]!.name).toBe("enter");
    expect(decodeKeys("\n")[0]!.name).toBe("enter");
    expect(decodeKeys("\x7f")[0]!.name).toBe("backspace");
    expect(decodeKeys("\t")[0]!.name).toBe("tab");
    expect(decodeKeys("\x03")[0]!.name).toBe("ctrl-c");
    expect(decodeKeys(`${ESC}[5~`)[0]!.name).toBe("pageup");
    expect(decodeKeys(`${ESC}[6~`)[0]!.name).toBe("pagedown");
    expect(decodeKeys(`${ESC}[H`)[0]!.name).toBe("home");
  });

  it("treats a lone escape as escape", () => {
    expect(decodeKeys(ESC)).toEqual([{ name: "escape", ch: "" }]);
  });

  it("decodes every keypress in a chunk, not just the first", () => {
    // Fast typing and pastes arrive as one chunk. Returning a single key
    // silently drops the rest of what the user typed.
    const keys = decodeKeys(`ab${ESC}[Bc\r`);
    expect(keys.map((k) => k.name)).toEqual(["char", "char", "down", "char", "enter"]);
    expect(keys.map((k) => k.ch).join("")).toBe("abc");
  });

  it("ignores control bytes that are not bound to anything", () => {
    expect(decodeKeys("\x01\x02")).toEqual([]);
  });

  it("reports editing keys in sequence rather than applying them", () => {
    // The decoder's job is to say what was pressed; the screen decides what
    // a backspace means. Keeping that split is why the same decoder serves
    // the search box and the add form.
    const keys = decodeKeys("git\x7fhub");
    expect(keys.map((k) => k.name)).toEqual([
      "char",
      "char",
      "char",
      "backspace",
      "char",
      "char",
      "char",
    ]);
  });
});

describe("visibleLength", () => {
  it("counts glyphs, not escape sequences", () => {
    expect(visibleLength("abc")).toBe(3);
    expect(visibleLength(`${ansi.bold}abc${ansi.reset}`)).toBe(3);
    expect(visibleLength(`${ansi.dim}${ansi.red}x${ansi.reset}`)).toBe(1);
  });

  it("is what keeps a highlighted row from wrapping", () => {
    // A styled row is much longer in bytes than on screen; padding to a
    // terminal width using raw .length would overflow every line.
    const styled = `${ansi.reverse}${ansi.cyan}entry${ansi.reset}`;
    expect(styled.length).toBeGreaterThan(visibleLength(styled));
    expect(visibleLength(styled)).toBe(5);
  });
});
