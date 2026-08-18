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

import { clipboardSink } from "../src/sinks.js";
import { mkdtemp, writeFile, readFile, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";

/**
 * A fake wl-copy/wl-paste pair backed by a state file, placed first on PATH.
 * clipboardSink tries wl-copy first, so these win over any real tools and the
 * test does not depend on a display or a system clipboard.
 */
async function fakeClipboard(): Promise<{ dir: string; stateFile: string; restore: () => void }> {
  const dir = await mkdtemp(join(tmpdir(), "seedpass-clip-"));
  const stateFile = join(dir, "clip.txt");
  await writeFile(stateFile, "");
  await writeFile(join(dir, "wl-copy"), `#!/bin/sh\ncat > "${stateFile}"\n`);
  // -n: no trailing newline, matching the real wl-paste flag clipboardSink uses.
  await writeFile(join(dir, "wl-paste"), `#!/bin/sh\ncat "${stateFile}"\n`);
  await chmod(join(dir, "wl-copy"), 0o755);
  await chmod(join(dir, "wl-paste"), 0o755);
  const savedPath = process.env["PATH"];
  process.env["PATH"] = `${dir}:${savedPath ?? ""}`;
  return {
    dir,
    stateFile,
    restore: () => {
      if (savedPath === undefined) delete process.env["PATH"];
      else process.env["PATH"] = savedPath;
    },
  };
}

describe("clipboardSink auto-clear", () => {
  it("copies the secret and, by default, never wipes it", async () => {
    const clip = await fakeClipboard();
    try {
      await clipboardSink("s3cr3t");
      expect(await readFile(clip.stateFile, "utf8")).toBe("s3cr3t");
      // No clear scheduled: it stays put.
      await new Promise((r) => setTimeout(r, 250));
      expect(await readFile(clip.stateFile, "utf8")).toBe("s3cr3t");
    } finally {
      clip.restore();
    }
  });

  it("wipes the secret after the delay when it is still ours", async () => {
    const clip = await fakeClipboard();
    try {
      const r = await clipboardSink("wipe-me", { clearAfterSeconds: 0.15 });
      expect(r.detail).toContain("clears in");
      expect(await readFile(clip.stateFile, "utf8")).toBe("wipe-me");
      await new Promise((res) => setTimeout(res, 400));
      expect(await readFile(clip.stateFile, "utf8")).toBe("");
    } finally {
      clip.restore();
    }
  });

  it("leaves a value the user copied since the secret untouched", async () => {
    const clip = await fakeClipboard();
    try {
      await clipboardSink("old-secret", { clearAfterSeconds: 0.15 });
      // The user copies something else before the timer fires.
      await writeFile(clip.stateFile, "user's own copy");
      await new Promise((res) => setTimeout(res, 400));
      expect(await readFile(clip.stateFile, "utf8")).toBe("user's own copy");
    } finally {
      clip.restore();
    }
  });
});
