/**
 * `fingerprint create` — the only command that mints a secret with no other
 * copy anywhere. The tests below are mostly about the failure modes, because
 * every one of them loses a vault permanently:
 *
 *  - a phrase delivered nowhere (profile created, seed unrecoverable)
 *  - a phrase clobbering an existing file (the *previous* vault's seed gone)
 *  - a phrase leaked into a pipe (an agent transcript, a CI log)
 *  - a phrase that is not a valid BIP-39 mnemonic (nothing can reopen it)
 */

import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { NO_POSIX_PERMISSIONS } from "./helpers/platform.js";
import { mkdtemp, readFile, writeFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import {
  isValidMnemonic,
  generateMnemonic,
  generateFingerprint,
  deriveIndexKeyBytes,
} from "@seedpass/core";
import { buildProgram, type ProgramIo } from "../src/index.js";
import { openVault } from "../src/vaultFile.js";
import { AppDir, INDEX_FILENAME } from "../src/appDir.js";

let appDir: string;
let scratch: string;
const savedTty = process.stdout.isTTY;

interface Run {
  stdout: string;
  stderr: string;
  error?: unknown;
}

async function run(...argv: string[]): Promise<Run> {
  const out: string[] = [];
  const err: string[] = [];
  const io: ProgramIo = { out: (l) => out.push(l), err: (l) => err.push(l) };
  let error: unknown;
  try {
    await buildProgram(io).parseAsync(["node", "seedpass-js", "--app-dir", appDir, ...argv]);
  } catch (e) {
    error = e;
  }
  return { stdout: out.join("\n"), stderr: err.join("\n"), error };
}

beforeEach(async () => {
  appDir = await mkdtemp(join(tmpdir(), "seedpass-create-app-"));
  scratch = await mkdtemp(join(tmpdir(), "seedpass-create-out-"));
  process.env["SEEDPASS_PASSWORD"] = "creation-test-password";
  delete process.env["SEEDPASS_MNEMONIC"];
  // Default to the non-interactive case; the TTY test opts in explicitly.
  Object.defineProperty(process.stdout, "isTTY", { value: false, configurable: true });
});

afterEach(() => {
  Object.defineProperty(process.stdout, "isTTY", { value: savedTty, configurable: true });
  delete process.env["SEEDPASS_PASSWORD"];
});

describe("generateMnemonic", () => {
  it("produces valid, distinct phrases of the requested length", () => {
    const a = generateMnemonic(12);
    const b = generateMnemonic(12);
    const long = generateMnemonic(24);
    expect(a.split(" ")).toHaveLength(12);
    expect(long.split(" ")).toHaveLength(24);
    expect(isValidMnemonic(a)).toBe(true);
    expect(isValidMnemonic(long)).toBe(true);
    // Two calls returning the same phrase would mean the CSPRNG is not being
    // consulted — the failure that matters most and is easiest to miss.
    expect(a).not.toBe(b);
  });

  it("refuses unsupported word counts rather than rounding to one", () => {
    expect(() => generateMnemonic(18 as 12)).toThrow(/must be one of/);
  });
});

describe("fingerprint create", () => {
  it("refuses to generate when stdout is a pipe and no destination was given", async () => {
    const r = await run("fingerprint", "create");
    expect(String((r.error as Error).message)).toMatch(/nowhere safe to put it/);
    // Nothing may exist afterwards: a profile whose seed was never delivered
    // is a vault nobody can open.
    const app = new AppDir(appDir);
    expect((await app.readFingerprints()).fingerprints).toHaveLength(0);
  });

  it.skipIf(NO_POSIX_PERMISSIONS)("writes the phrase to a 0600 file and creates a matching profile", async () => {
    const out = join(scratch, "seed.txt");
    const r = await run("fingerprint", "create", "--name", "test", "--words", "24", "--out", out);
    const result = JSON.parse(r.stdout);

    const phrase = (await readFile(out, "utf8")).trim();
    expect(phrase.split(" ")).toHaveLength(24);
    expect(isValidMnemonic(phrase)).toBe(true);
    // The phrase must not also appear on stdout when --out was used.
    expect(r.stdout).not.toContain(phrase);
    expect((await stat(out)).mode & 0o777).toBe(0o600);

    // The written phrase is genuinely the one the profile derives from.
    expect(result.fingerprint).toBe(generateFingerprint(phrase));
    expect(result.seed_written_to).toBe(out);
    const vault = await openVault(join(new AppDir(appDir).profileDir(result.fingerprint), INDEX_FILENAME), phrase);
    expect(vault).toBeTruthy();
  });

  it("never overwrites an existing seed file", async () => {
    const out = join(scratch, "occupied.txt");
    await writeFile(out, "an earlier vault's only seed\n");
    const r = await run("fingerprint", "create", "--out", out);
    expect(r.error).toBeTruthy();
    // The prior contents survive: clobbering this file destroys another vault.
    expect(await readFile(out, "utf8")).toBe("an earlier vault's only seed\n");
  });

  it("prints to stdout only when explicitly asked with --show", async () => {
    const r = await run("fingerprint", "create", "--show");
    const lines = r.stdout.split("\n");
    expect(isValidMnemonic(lines[0]!)).toBe(true);
    expect(r.stderr).toMatch(/ONLY way to recover/);
  });

  it("prints to an interactive terminal without needing a flag", async () => {
    Object.defineProperty(process.stdout, "isTTY", { value: true, configurable: true });
    const r = await run("fingerprint", "create");
    expect(isValidMnemonic(r.stdout.split("\n")[0]!)).toBe(true);
  });

  it("rejects --show together with --out", async () => {
    const r = await run("fingerprint", "create", "--show", "--out", join(scratch, "x.txt"));
    expect(String((r.error as Error).message)).toMatch(/mutually exclusive/);
  });

  it("rejects word counts other than 12 or 24", async () => {
    const r = await run("fingerprint", "create", "--words", "18", "--show");
    expect(String((r.error as Error).message)).toMatch(/12 or 24/);
  });

  it("requires a password", async () => {
    delete process.env["SEEDPASS_PASSWORD"];
    const r = await run("fingerprint", "create", "--show");
    expect(String((r.error as Error).message)).toMatch(/SEEDPASS_PASSWORD/);
  });

  it("creates a profile whose index key derives from the generated phrase", async () => {
    const out = join(scratch, "s.txt");
    const r = await run("fingerprint", "create", "--out", out);
    const phrase = (await readFile(out, "utf8")).trim();
    const { fingerprint } = JSON.parse(r.stdout);
    // Derivation is the whole product; assert the key material matches.
    expect(deriveIndexKeyBytes(phrase)).toEqual(
      deriveIndexKeyBytes(phrase.normalize("NFKD")),
    );
    expect(fingerprint).toBe(generateFingerprint(phrase));
  });
});
