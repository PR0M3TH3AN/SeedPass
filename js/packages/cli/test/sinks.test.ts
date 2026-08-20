/**
 * Sink command-spec parsing.
 *
 * `--exec 'sh -c "..."'` is the most common sink invocation there is, and
 * splitting the spec on whitespace alone broke exactly that shape: sh
 * received the fragments of the quoted script as separate argv entries and
 * died on an unterminated string.
 */

import { describe, expect, it } from "vitest";
import { NO_CLIPBOARD } from "./helpers/platform.js";
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
  it.skipIf(NO_CLIPBOARD)("copies the secret and, by default, never wipes it", async () => {
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

  it.skipIf(NO_CLIPBOARD)("wipes the secret after the delay when it is still ours", async () => {
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
})

describe("command spec parsing keeps every argument", () => {
  it("does not tokenize when more than one element was supplied", () => {
    // Mutation testing found this unguarded: turning the `&&` into `||` makes
    // a multi-element spec whose FIRST element contains whitespace get
    // tokenized, silently discarding every element after it. Losing an
    // argument changes which command runs — dropping a `--dry-run` or a
    // target path is exactly the kind of silent change that matters for a
    // sink handed a secret.
    expect(parseCommandSpec(["echo hi", "there"])).toEqual(["echo hi", ["there"]]);
    expect(parseCommandSpec(["wc", "-c"])).toEqual(["wc", ["-c"]]);
    expect(parseCommandSpec(["a b", "c d", "e"])).toEqual(["a b", ["c d", "e"]]);
  });

  it("tokenizes only a lone element containing whitespace", () => {
    expect(parseCommandSpec(["wc -c"])).toEqual(["wc", ["-c"]]);
    // A lone element with no whitespace needs no splitting, and splitting it
    // must not change it.
    expect(parseCommandSpec(["ls"])).toEqual(["ls", []]);
  });

  it("refuses an empty command rather than running something unintended", () => {
    expect(() => parseCommandSpec([])).toThrow(/empty command/);
    expect(() => parseCommandSpec([""])).toThrow(/empty command/);
  });
});

import { sinkEnv } from "../src/sinks.js";

describe("the environment a sink child receives", () => {
  it("passes only the allowlist through, and never the caller's own env", async () => {
    process.env["SEEDPASS_TEST_LEAK"] = "must-not-appear";
    try {
      const env = sinkEnv();
      expect(env["SEEDPASS_TEST_LEAK"]).toBeUndefined();
      // PATH is on the allowlist and the child genuinely needs it, so its
      // presence is what proves the allowlist is being applied rather than
      // the whole environment simply being empty.
      expect(env["PATH"]).toBe(process.env["PATH"]);
    } finally {
      delete process.env["SEEDPASS_TEST_LEAK"];
    }
  });

  it("drops a SEEDPASS_ variable even if the allowlist grows one", async () => {
    // The backstop. It cannot fire against today's allowlist — which is why
    // deleting it changed nothing anywhere — so the allowlist is injected
    // here to stand in for the future edit that adds one by mistake.
    process.env["SEEDPASS_SNEAKY"] = "must-not-appear";
    try {
      const env = sinkEnv({}, ["PATH", "SEEDPASS_SNEAKY"]);
      expect(env["SEEDPASS_SNEAKY"]).toBeUndefined();
      expect(env["PATH"]).toBeDefined();
    } finally {
      delete process.env["SEEDPASS_SNEAKY"];
    }
  });

  it("still injects the exec sink's own secret variable", async () => {
    // `extra` is deliberately exempt from the SEEDPASS_ rule: handing the
    // secret to the child through the environment is the exec sink's entire
    // job. A backstop that swallowed it would break the feature.
    const env = sinkEnv({ SEEDPASS_SECRET: "the-secret" });
    expect(env["SEEDPASS_SECRET"]).toBe("the-secret");
  });
});

describe("command specs on Windows", () => {
  /**
   * `windows` is an explicit parameter so both branches run on any machine.
   * Without that, the Windows branch could only ever execute on Windows —
   * which is precisely how this survived: the JavaScript suite had never run
   * there until 2026-08-20, and when it did, three sink tests failed at once.
   *
   * The bug: tokenize treated backslash as a POSIX escape unconditionally, so
   * every Windows path handed to --exec or --stdin-to lost its separators
   * before it was spawned.
   */
  it("keeps the separators in a Windows path", () => {
    expect(parseCommandSpec(["C:\\Tools\\bin.exe -c"], { windows: true })).toEqual([
      "C:\\Tools\\bin.exe",
      ["-c"],
    ]);
  });

  it("keeps them inside quotes too, where a path with spaces has to live", () => {
    expect(
      parseCommandSpec(['"C:\\Program Files\\tool.exe" --flag'], { windows: true }),
    ).toEqual(["C:\\Program Files\\tool.exe", ["--flag"]]);
  });

  it("pins what the POSIX branch does to the same input", () => {
    // Not a hypothetical. This is what every Windows user got: a command
    // named "C:Program" and an argument called "Filestool.exe".
    expect(
      parseCommandSpec(['"C:\\Program Files\\tool.exe" --flag'], { windows: false }),
    ).toEqual(["C:Program Filestool.exe", ["--flag"]]);
  });

  it("still escapes on POSIX, where a shell would", () => {
    expect(parseCommandSpec(["printf a\\ b"], { windows: false })).toEqual([
      "printf",
      ["a b"],
    ]);
  });

  it("quoting still groups on Windows", () => {
    expect(parseCommandSpec(['sh -c "do the thing"'], { windows: true })).toEqual([
      "sh",
      ["-c", "do the thing"],
    ]);
  });
});
