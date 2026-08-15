/**
 * Sink command-spec parsing.
 *
 * `--exec 'sh -c "..."'` is the most common sink invocation there is, and
 * splitting the spec on whitespace alone broke exactly that shape: sh
 * received the fragments of the quoted script as separate argv entries and
 * died on an unterminated string.
 */

import { describe, expect, it } from "vitest";
import { parseCommandSpec } from "../src/sinks.js";

describe("parseCommandSpec", () => {
  it("keeps a pre-split argv untouched", () => {
    expect(parseCommandSpec(["wc", "-c"])).toEqual(["wc", ["-c"]]);
  });

  it("splits a single quoted spec on whitespace", () => {
    expect(parseCommandSpec(["wc -c"])).toEqual(["wc", ["-c"]]);
  });

  it("treats a double-quoted section as one argument", () => {
    expect(parseCommandSpec(['sh -c "echo hello world"'])).toEqual([
      "sh",
      ["-c", "echo hello world"],
    ]);
  });

  it("treats a single-quoted section as one argument", () => {
    expect(parseCommandSpec(["sh -c 'echo hello world'"])).toEqual([
      "sh",
      ["-c", "echo hello world"],
    ]);
  });

  it("supports quotes nested inside the other quote style", () => {
    expect(parseCommandSpec(["sh -c \"echo 'hi there'\""])).toEqual([
      "sh",
      ["-c", "echo 'hi there'"],
    ]);
  });

  it("honours backslash escapes outside single quotes", () => {
    expect(parseCommandSpec(["cmd a\\ b"])).toEqual(["cmd", ["a b"]]);
    expect(parseCommandSpec(["cmd 'a\\ b'"])).toEqual(["cmd", ["a\\ b"]]);
  });

  it("collapses runs of whitespace", () => {
    expect(parseCommandSpec(["  wc   -c  "])).toEqual(["wc", ["-c"]]);
  });

  it("does not expand variables — no shell is involved", () => {
    // The secret arrives via the environment; a spec that looks like a shell
    // expansion must reach the child literally rather than being substituted
    // by us.
    expect(parseCommandSpec(["cmd $SEEDPASS_SECRET"])).toEqual([
      "cmd",
      ["$SEEDPASS_SECRET"],
    ]);
  });

  it("rejects an unterminated quote instead of guessing", () => {
    expect(() => parseCommandSpec(['sh -c "oops'])).toThrow(/unterminated double quote/);
    expect(() => parseCommandSpec(["sh -c 'oops"])).toThrow(/unterminated single quote/);
  });

  it("rejects an empty command", () => {
    expect(() => parseCommandSpec([""])).toThrow(/empty command/);
  });
});
