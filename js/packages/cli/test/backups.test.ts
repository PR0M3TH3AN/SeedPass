/**
 * Rolling index backups (parity with Python's BackupManager).
 *
 * The setting these serve was previously inert: the TUI accepted an
 * "additional backup location", replied that backups would be written there,
 * and no code path ever wrote one. That is worse than having no setting at
 * all — it is false assurance in the one feature a user leans on precisely
 * when everything else has gone wrong. These tests exist to keep it real.
 *
 * Filenames must match Python's byte for byte, because the two
 * implementations share a profile directory and either may be asked to
 * restore from the other's snapshots.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtemp, mkdir, readdir, readFile, writeFile, stat } from "node:fs/promises";
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
  type VaultIndex,
} from "@seedpass/core";
import { buildProgram, type ProgramIo } from "../src/index.js";
import { AppDir, INDEX_FILENAME } from "../src/appDir.js";
import { createIndexBackup, backupFilename, BACKUP_DIR_NAME } from "../src/backups.js";

const MNEMONIC = mnemonics["abandon12"]!;
const FINGERPRINT = generateFingerprint(MNEMONIC);

let appDir: string;
let profileDir: string;
let indexPath: string;

async function run(...argv: string[]): Promise<string> {
  const out: string[] = [];
  const io: ProgramIo = { out: (l: string) => out.push(l), err: () => {} };
  await buildProgram(io).parseAsync(["node", "seedpass-js", "--app-dir", appDir, ...argv]);
  return out.join("\n");
}

beforeEach(async () => {
  appDir = await mkdtemp(join(tmpdir(), "seedpass-backups-"));
  const app = new AppDir(appDir);
  await app.mutateFingerprints((data) => {
    data.fingerprints.push(FINGERPRINT);
    data.names[FINGERPRINT] = "main";
    data.last_used = FINGERPRINT;
  });
  profileDir = app.profileDir(FINGERPRINT);
  await mkdir(profileDir, { recursive: true });
  const index = { schema_version: 4, entries: {} } as VaultIndex;
  addPasswordEntry(index, "seed.example", 16, {});
  indexPath = join(profileDir, INDEX_FILENAME);
  await writeFile(
    indexPath,
    await encryptV3(deriveIndexKeyBytes(MNEMONIC), utf8(JSON.stringify(index))),
  );
  process.env["SEEDPASS_MNEMONIC"] = MNEMONIC;
});

afterEach(() => {
  delete process.env["SEEDPASS_MNEMONIC"];
});

async function backupNames(): Promise<string[]> {
  try {
    return (await readdir(join(profileDir, BACKUP_DIR_NAME))).sort();
  } catch {
    return [];
  }
}

describe("createIndexBackup", () => {
  it("writes a Python-named snapshot at 0600 and copies the ciphertext verbatim", async () => {
    const result = await createIndexBackup({ indexPath, config: {}, now: 1111 });
    expect(result.written).toBe(join(profileDir, BACKUP_DIR_NAME, backupFilename(1111)));
    // Exactly Python's BACKUP_FILENAME_TEMPLATE.
    expect(backupFilename(1111)).toBe("entries_db_backup_1111.json.enc");

    const mode = (await stat(result.written!)).mode & 0o777;
    expect(mode).toBe(0o600);

    // A copy of the encrypted file — the backup path never decrypts anything.
    expect(await readFile(result.written!)).toEqual(await readFile(indexPath));
  });

  it("mirrors to additional_backup_path, prefixed by fingerprint as Python does", async () => {
    const extra = await mkdtemp(join(tmpdir(), "seedpass-extra-"));
    const result = await createIndexBackup({
      indexPath,
      config: { additional_backup_path: extra },
      now: 2222,
    });
    const expected = join(extra, `${FINGERPRINT}_${backupFilename(2222)}`);
    expect(result.mirrored).toBe(expected);
    expect((await stat(expected)).mode & 0o777).toBe(0o600);
    expect(await readFile(expected)).toEqual(await readFile(indexPath));
  });

  it("creates the additional location if it does not exist yet", async () => {
    const extra = join(await mkdtemp(join(tmpdir(), "seedpass-extra-")), "nested", "dir");
    const result = await createIndexBackup({
      indexPath,
      config: { additional_backup_path: extra },
      now: 3333,
    });
    expect(result.mirrored).toContain("nested");
    expect(result.mirrorError).toBeUndefined();
  });

  it("reports a failed mirror instead of failing the backup", async () => {
    // A path whose parent is a FILE cannot be made into a directory.
    const blocker = join(profileDir, "not-a-dir");
    await writeFile(blocker, "x");
    const result = await createIndexBackup({
      indexPath,
      config: { additional_backup_path: join(blocker, "sub") },
      now: 4444,
    });
    // The primary snapshot still landed; only the mirror failed, and it said so.
    expect(result.written).not.toBeNull();
    expect(result.mirrorError).toBeTruthy();
    expect(result.mirrored).toBeUndefined();
  });

  it("honours backup_interval, and does not throttle when it is 0", async () => {
    await createIndexBackup({ indexPath, config: { backup_interval: 600 }, now: 5000 });
    // Inside the window: skipped.
    const throttled = await createIndexBackup({
      indexPath, config: { backup_interval: 600 }, now: 5100,
    });
    expect(throttled.written).toBeNull();
    expect(throttled.skipped).toBe("throttled");
    // Past the window: written.
    const later = await createIndexBackup({
      indexPath, config: { backup_interval: 600 }, now: 5700,
    });
    expect(later.written).not.toBeNull();
    // Default config has no interval, so every write snapshots.
    const always = await createIndexBackup({ indexPath, config: {}, now: 5701 });
    expect(always.written).not.toBeNull();
  });

  it("skips quietly when there is no index to copy", async () => {
    const result = await createIndexBackup({
      indexPath: join(profileDir, "missing.enc"), config: {}, now: 6000,
    });
    expect(result.written).toBeNull();
    expect(result.skipped).toBe("no-index");
  });
});

describe("the CLI snapshots the vault on every mutation", () => {
  it("writes a backup when an entry is added", async () => {
    expect(await backupNames()).toHaveLength(0);
    await run("entry", "add", "password", "added.example", "--length", "16");
    const names = await backupNames();
    expect(names).toHaveLength(1);
    expect(names[0]).toMatch(/^entries_db_backup_\d+\.json\.enc$/);
  });

  it("mirrors CLI mutations to the configured additional location", async () => {
    const extra = await mkdtemp(join(tmpdir(), "seedpass-cli-extra-"));
    await run("config", "set", "additional_backup_path", extra);
    await run("entry", "add", "password", "mirrored.example", "--length", "16");
    const mirrored = await readdir(extra);
    expect(mirrored).toHaveLength(1);
    expect(mirrored[0]).toMatch(new RegExp(`^${FINGERPRINT}_entries_db_backup_\\d+\\.json\\.enc$`));
  });

  it("does not let an unwritable additional location fail the mutation", async () => {
    const blocker = join(profileDir, "blocker-file");
    await writeFile(blocker, "x");
    await run("config", "set", "additional_backup_path", join(blocker, "sub"));
    // The entry must still be added, and the command must not throw.
    await run("entry", "add", "password", "survives.example", "--length", "16");
    const rows = JSON.parse(await run("entry", "list")) as { label: string }[];
    expect(rows.map((r) => r.label)).toContain("survives.example");
  });
});
