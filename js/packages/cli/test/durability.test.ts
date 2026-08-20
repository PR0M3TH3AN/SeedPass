/**
 * Durability and input-validation guarantees for vault writes.
 *
 * From a security review: a bad numeric option once persisted NaN as JSON
 * null and made every later open fail; writes truncated the target in place
 * with no lock, so a crash or a concurrent command could lose the vault.
 */

import { beforeAll, describe, expect, it } from "vitest";
import { NO_POSIX_PERMISSIONS } from "./helpers/platform.js";
import { mkdtemp, readFile, writeFile, stat, chmod } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import { mnemonics, entriesIndex } from "@seedpass/test-vectors";
import { deriveIndexKeyBytes, encryptV3, utf8 } from "@seedpass/core";
import { buildProgram, AppDir, type ProgramIo } from "../src/index.js";

const MNEMONIC = mnemonics["abandon12"]!;
let vaultPath: string;
let dir: string;

async function run(...argv: string[]): Promise<{ stdout: string; error?: unknown }> {
  const out: string[] = [];
  const io: ProgramIo = { out: (l: string) => out.push(l), err: () => {} };
  let error: unknown;
  const saved = process.env["SEEDPASS_MNEMONIC"];
  process.env["SEEDPASS_MNEMONIC"] = MNEMONIC;
  try {
    await buildProgram(io).parseAsync(["node", "seedpass-js", ...argv]);
  } catch (e) {
    error = e;
  } finally {
    if (saved === undefined) delete process.env["SEEDPASS_MNEMONIC"];
    else process.env["SEEDPASS_MNEMONIC"] = saved;
  }
  return { stdout: out.join("\n"), error };
}

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "seedpass-durability-"));
  vaultPath = join(dir, "vault.enc");
  await writeFile(
    vaultPath,
    await encryptV3(deriveIndexKeyBytes(MNEMONIC), utf8(JSON.stringify(entriesIndex.entries))),
  );
});

describe("numeric input validation", () => {
  it("rejects a non-numeric length instead of persisting NaN", async () => {
    const before = await readFile(vaultPath);
    const r = await run("--vault", vaultPath, "entry", "add", "password", "bad", "--length", "not-a-number");
    expect(String((r.error as Error).message)).toContain("whole number");
    // The vault is untouched and still opens
    expect(await readFile(vaultPath)).toEqual(before);
    expect((await run("--vault", vaultPath, "entry", "list")).error).toBeUndefined();
  });

  it("rejects out-of-range and fractional values", async () => {
    for (const bad of ["0", "5", "999", "16.5", "1e3", "", " "]) {
      const r = await run("--vault", vaultPath, "entry", "add", "password", "bad", "--length", bad);
      expect(r.error, `--length ${JSON.stringify(bad)} should be refused`).toBeTruthy();
    }
    const totp = await run(
      "--vault", vaultPath, "entry", "add", "totp", "bad", "--period", "abc",
    );
    expect(String((totp.error as Error).message)).toContain("whole number");
  });

  it("still accepts valid values", async () => {
    const r = await run("--vault", vaultPath, "entry", "add", "password", "good", "--length", "24");
    expect(r.error).toBeUndefined();
    expect(JSON.parse(r.stdout).length).toBe(24);
  });
});

describe("atomic, permission-correct writes", () => {
  it.skipIf(NO_POSIX_PERMISSIONS)("leaves no temp files and keeps the vault at 0600", async () => {
    await chmod(vaultPath, 0o644); // simulate a loosened file
    await run("--vault", vaultPath, "entry", "add", "key-value", "perm", "k", "v");
    const info = await stat(vaultPath);
    // writeFile's mode only applies on creation, so this must be repaired
    expect(info.mode & 0o077).toBe(0);
    const leftovers = (await import("node:fs/promises")).readdir(dir);
    expect((await leftovers).filter((f) => f.includes(".tmp"))).toEqual([]);
    expect(existsSync(`${vaultPath}.lock`)).toBe(false);
  });

  it("survives concurrent writers without losing entries", async () => {
    const labels = ["c1", "c2", "c3", "c4", "c5"];
    await Promise.all(
      labels.map((label) =>
        run("--vault", vaultPath, "entry", "add", "key-value", label, "k", "v"),
      ),
    );
    const rows = JSON.parse((await run("--vault", vaultPath, "entry", "list")).stdout) as {
      label: string;
    }[];
    const seen = rows.map((r) => r.label);
    // Without locking, concurrent read-modify-write cycles silently drop
    // entries; every one of these must be present.
    for (const label of labels) expect(seen).toContain(label);
  });
});

describe("secrets on the command line", () => {
  it("warns when a secret arrives as an argument", async () => {
    const out: string[] = [];
    const err: string[] = [];
    const io: ProgramIo = { out: (l) => out.push(l), err: (l) => err.push(l) };
    const saved = process.env["SEEDPASS_MNEMONIC"];
    process.env["SEEDPASS_MNEMONIC"] = MNEMONIC;
    try {
      await buildProgram(io).parseAsync([
        "node", "seedpass-js", "--vault", vaultPath,
        "entry", "add", "key-value", "argv-secret", "k", "exposed-on-argv",
      ]);
    } finally {
      if (saved === undefined) delete process.env["SEEDPASS_MNEMONIC"];
      else process.env["SEEDPASS_MNEMONIC"] = saved;
    }
    expect(err.join("\n")).toContain("shell history");
    // The warning must not repeat the secret it is warning about
    expect(err.join("\n")).not.toContain("exposed-on-argv");
  });
});

describe("profile path validation", () => {
  it("refuses a fingerprint that is not 16 hex characters", async () => {
    const app = new AppDir(dir);
    expect(() => app.profileDir("../../etc")).toThrow(/invalid profile fingerprint/);
    await expect(app.removeProfile("../../etc")).rejects.toThrow(/invalid profile fingerprint/);
    await expect(app.switchProfile("nope")).rejects.toThrow(/invalid profile fingerprint/);
  });

  it("ignores malformed entries in the fingerprint registry", async () => {
    const appRoot = await mkdtemp(join(tmpdir(), "seedpass-registry-"));
    await writeFile(
      join(appRoot, "fingerprints.json"),
      JSON.stringify({
        fingerprints: ["../../evil", "0123456789ABCDEF"],
        last_used: "../../evil",
        names: {},
      }),
    );
    const app = new AppDir(appRoot);
    const data = await app.readFingerprints();
    expect(data.fingerprints).toEqual(["0123456789ABCDEF"]);
    expect(data.last_used).toBeNull();
  });
});
