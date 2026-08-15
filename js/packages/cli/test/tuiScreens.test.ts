/**
 * The interactive screens, driven through a fake terminal.
 *
 * The load-bearing assertions are the same agent-blind properties the CLI is
 * held to (plan section 9.3), because the TUI is now the default entry point
 * and renders the whole vault by itself:
 *
 *   - no screen shows a secret until `r` is pressed
 *   - `c` copies without ever drawing the value
 *   - dismissing a reveal removes the value from the next frame
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import { mnemonics } from "@seedpass/test-vectors";
import {
  generateFingerprint,
  deriveIndexKeyBytes,
  encryptV3,
  utf8,
  addPasswordEntry,
  addKeyValueEntry,
  type VaultIndex,
} from "@seedpass/core";
import { runTui, type TerminalLike } from "../src/tui/app.js";
import { decodeKeys, visibleLength, type Key } from "../src/tui/terminal.js";
import { AppDir, INDEX_FILENAME } from "../src/appDir.js";

const MNEMONIC = mnemonics["abandon12"]!;
const FINGERPRINT = generateFingerprint(MNEMONIC);
const SECRET_VALUE = "tui-stored-secret-value";

let appDir: string;

/** A terminal that records frames and lets a test press keys. */
class FakeTerminal implements TerminalLike {
  readonly columns = 100;
  readonly rows = 30;
  frames: string[][] = [];
  private handler: ((key: Key) => void) | null = null;
  restored = false;

  start(): void {}
  restore(): void {
    this.restored = true;
  }
  onKey(handler: (key: Key) => void): void {
    this.handler = handler;
  }
  onResize(): void {}
  draw(lines: string[]): void {
    this.frames.push(lines);
  }

  /** Feed keystrokes the way the real decoder would produce them. */
  async press(input: string): Promise<void> {
    for (const key of decodeKeys(input)) {
      // Sample the frame count BEFORE dispatching: a key handled entirely
      // synchronously (dismissing the reveal or help overlay) has already
      // drawn by the time the handler returns, and sampling afterwards made
      // settle() wait out its deadline for a second frame that never came.
      const before = this.frames.length;
      this.handler?.(key);
      await this.settle(before);
    }
  }

  /**
   * Wait for the keypress to actually reach the screen, then for the screen
   * to stop changing.
   *
   * Waiting only for "no change for a while" is not enough, and produced a
   * genuinely confusing hang: a mutation reopens the vault, which re-derives
   * the index key through PBKDF2 and takes about a second, during which
   * nothing is drawn at all. A quiet-only wait returned immediately, the next
   * keystroke landed on the screen that was still up, and the test typed its
   * "q" into a form field instead of quitting.
   *
   * Every handled key ends in a render, so waiting for one new frame is the
   * reliable signal. Quitting is the exception — it restores the terminal
   * instead of drawing — hence the second exit condition.
   */
  private async settle(before: number, quietMs = 60, timeoutMs = 15_000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (this.frames.length === before && !this.restored && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 10));
    }
    let seen = this.frames.length;
    let quietSince = Date.now();
    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 10));
      if (this.frames.length !== seen) {
        seen = this.frames.length;
        quietSince = Date.now();
        continue;
      }
      if (Date.now() - quietSince >= quietMs) return;
    }
  }

  get lastFrame(): string {
    return (this.frames.at(-1) ?? []).join("\n");
  }

  /** Everything ever drawn — for "this never appeared on screen" checks. */
  get everything(): string {
    return this.frames.flat().join("\n");
  }
}

async function buildVault(): Promise<void> {
  appDir = await mkdtemp(join(tmpdir(), "seedpass-tui-"));
  const app = new AppDir(appDir);
  const index: VaultIndex = { schema_version: 4, entries: {} } as VaultIndex;
  addPasswordEntry(index, "github.com", 20, { username: "adam" });
  addPasswordEntry(index, "gitlab.com", 16, {});
  addKeyValueEntry(index, "ci-token", "CI_TOKEN", SECRET_VALUE);
  addPasswordEntry(index, "aws-prod", 24, {});

  const dir = app.profileDir(FINGERPRINT);
  await app.mutateFingerprints((data) => {
    data.fingerprints.push(FINGERPRINT);
    data.names[FINGERPRINT] = "daily";
    data.last_used = FINGERPRINT;
  });
  const { mkdir } = await import("node:fs/promises");
  await mkdir(dir, { recursive: true });
  await writeFile(
    join(dir, INDEX_FILENAME),
    await encryptV3(deriveIndexKeyBytes(MNEMONIC), utf8(JSON.stringify(index))),
  );
}

/** Start the TUI and return once it has drawn its first frame. */
async function launch(): Promise<{ term: FakeTerminal; exit: Promise<number> }> {
  const term = new FakeTerminal();
  const exit = runTui({ appDir }, term);
  // Let unlock + first render complete.
  for (let i = 0; i < 50 && term.frames.length === 0; i++) {
    await new Promise((r) => setTimeout(r, 10));
  }
  return { term, exit };
}

beforeEach(async () => {
  await buildVault();
  process.env["SEEDPASS_MNEMONIC"] = MNEMONIC;
});

afterEach(() => {
  delete process.env["SEEDPASS_MNEMONIC"];
  vi.restoreAllMocks();
});

describe("list screen", () => {
  it("shows every entry as a reference with its kind, and no secret", async () => {
    const { term, exit } = await launch();
    expect(term.lastFrame).toContain("sp://entry/0");
    expect(term.lastFrame).toContain("github.com");
    expect(term.lastFrame).toContain("ci-token");
    expect(term.lastFrame).toContain("4 entries");
    // The one entry with a stored secret must not render it anywhere.
    expect(term.everything).not.toContain(SECRET_VALUE);
    await term.press("q");
    expect(await exit).toBe(0);
  });

  it("filters as you type and clears on escape", async () => {
    const { term, exit } = await launch();
    await term.press("/git");
    expect(term.lastFrame).toContain("github.com");
    expect(term.lastFrame).toContain("gitlab.com");
    expect(term.lastFrame).not.toContain("aws-prod");
    await term.press("\x1b");
    expect(term.lastFrame).toContain("aws-prod");
    await term.press("q");
    await exit;
  });

  it("moves the selection with the arrow keys", async () => {
    const { term, exit } = await launch();
    await term.press("\x1b[B\x1b[B");
    await term.press("\r");
    // Detail of the third entry, reached by two downs and enter.
    expect(term.lastFrame).toContain("ci-token");
    expect(term.lastFrame).toContain("CI_TOKEN");
    expect(term.lastFrame).toContain("has_value");
    await term.press("q");
    await term.press("q");
    await exit;
  });
});

describe("secret handling", () => {
  it("shows a stored secret only after r, and hides it again on the next key", async () => {
    const { term, exit } = await launch();
    await term.press("\x1b[B\x1b[B"); // to ci-token
    const beforeReveal = term.frames.length;
    expect(term.everything).not.toContain(SECRET_VALUE);

    await term.press("r");
    expect(term.lastFrame).toContain(SECRET_VALUE);

    await term.press(" ");
    // Gone from the current frame; only the frames drawn while revealing
    // ever contained it.
    expect(term.lastFrame).not.toContain(SECRET_VALUE);
    const revealFrames = term.frames
      .slice(beforeReveal)
      .filter((f) => f.join("\n").includes(SECRET_VALUE));
    expect(revealFrames).toHaveLength(1);

    // Dismissing lands on the detail screen, where q means "back"; a second
    // q leaves the app.
    await term.press("qq");
    await exit;
  });

  it("copies without drawing the value", async () => {
    const { term, exit } = await launch();
    await term.press("\x1b[B\x1b[B");
    await term.press("c");
    // Either the clipboard tool is present or it is not; what matters is
    // that neither outcome puts the secret on screen.
    expect(term.everything).not.toContain(SECRET_VALUE);
    await term.press("q");
    await exit;
  });

  it("masks a secret being typed into the add form", async () => {
    const { term, exit } = await launch();
    await term.press("a");
    await term.press("\x1b[C\x1b[C"); // pick key-value
    await term.press("\r");
    await term.press("label-x\rKEY\rhunter2xyz");
    expect(term.lastFrame).not.toContain("hunter2xyz");
    expect(term.lastFrame).toContain("•".repeat("hunter2xyz".length));
    await term.press("\x1b");
    await term.press("q");
    await exit;
  });
});

describe("mutations", () => {
  it("adds a password entry and persists it to the vault", async () => {
    const { term, exit } = await launch();
    await term.press("a");
    await term.press("\r"); // password kind
    await term.press("new-site.example\r24\rbob\r");
    expect(term.lastFrame).toContain("new-site.example");
    await term.press("q");
    await exit;

    // Re-open from disk: the TUI must have written, not just redrawn.
    const { openVault } = await import("../src/vaultFile.js");
    const reopened = await openVault(
      join(new AppDir(appDir).profileDir(FINGERPRINT), INDEX_FILENAME),
      MNEMONIC,
    );
    const labels = Object.values(reopened.index.entries).map((e) => e.label);
    expect(labels).toContain("new-site.example");
  });

  it("rejects a nonsense password length instead of storing it", async () => {
    const { term, exit } = await launch();
    await term.press("a");
    await term.press("\r");
    await term.press("bad-length\rnot-a-number\r\r");
    // NaN once reached the vault through a --length flag and made the index
    // unreadable; the form must refuse the same input.
    expect(term.lastFrame).toContain("whole number");
    await term.press("\x1b");
    await term.press("q");
    await exit;
  });

  it("archives and unarchives the selected entry", async () => {
    const { term, exit } = await launch();
    await term.press("d");
    expect(term.lastFrame).toContain("archived github.com");
    expect(term.lastFrame).toContain("3 entries");
    await term.press("A");
    expect(term.lastFrame).toContain("4 entries");
    await term.press("q");
    await exit;
  });
});

describe("chrome", () => {
  it("lists the keys in help", async () => {
    const { term, exit } = await launch();
    await term.press("?");
    expect(term.lastFrame).toContain("copy secret to clipboard");
    expect(term.lastFrame).toContain("quit");
    await term.press(" ");
    await term.press("q");
    await exit;
  });

  it("never draws a line wider than the terminal", async () => {
    const { term, exit } = await launch();
    await term.press("/git");
    await term.press("\r");
    for (const frame of term.frames) {
      for (const line of frame) {
        // Counting glyphs, not escape bytes — a styled row that overflows
        // wraps and corrupts every frame after it.
        expect(visibleLength(line)).toBeLessThanOrEqual(term.columns);
      }
    }
    await term.press("q");
    await exit;
  });

  it("restores the terminal on exit", async () => {
    const { term, exit } = await launch();
    await term.press("q");
    await exit;
    expect(term.restored).toBe(true);
  });

  it("exits 130 on ctrl-c, as a signal-terminated program should", async () => {
    const { term, exit } = await launch();
    await term.press("\x03");
    expect(await exit).toBe(130);
    expect(term.restored).toBe(true);
  });
});
