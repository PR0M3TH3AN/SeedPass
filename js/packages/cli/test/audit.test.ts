/**
 * Audit chain tamper-evidence, including the head that pins the log's length.
 *
 * The scenario that motivated these: chain linkage alone verifies a truncated
 * log perfectly, the head catches that, and the head sits beside the log with
 * the same permissions — so deleting one more file must fail verification
 * too, or the whole defense is one `rm` away from disabled.
 */

import { describe, expect, it, beforeEach } from "vitest";
import { mkdtemp, readFile, writeFile, rm, copyFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLog } from "../src/audit.js";

const KEY = new Uint8Array(32).fill(7);
let dir: string;
let logPath: string;
let headPath: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "seedpass-audit-"));
  logPath = join(dir, "audit.log");
  headPath = `${logPath}.head`;
});

async function writeRecords(n: number): Promise<void> {
  const log = new AuditLog(logPath, KEY);
  for (let i = 0; i < n; i++) await log.log("event", { i });
}

async function truncateLastLine(): Promise<void> {
  const lines = (await readFile(logPath, "utf8")).split("\n").filter((l) => l.trim());
  await writeFile(logPath, lines.slice(0, -1).join("\n") + "\n");
}

describe("AuditLog.verify", () => {
  it("verifies an intact chain", async () => {
    await writeRecords(3);
    expect((await AuditLog.verify(logPath, KEY)).length).toBe(3);
  });

  it("catches truncation when the head survives", async () => {
    await writeRecords(3);
    await truncateLastLine();
    await expect(AuditLog.verify(logPath, KEY)).rejects.toThrow(/removed|head/);
  });

  it("catches truncation even when the head is deleted with it", async () => {
    // The attack the head-required rule exists for: shorten the log AND
    // remove the sidecar that records its length. This verified clean before.
    await writeRecords(3);
    await truncateLastLine();
    await rm(headPath);
    await expect(AuditLog.verify(logPath, KEY)).rejects.toThrow(/no head/);
  });

  it("rejects a non-empty log with no head at all", async () => {
    await writeRecords(2);
    await rm(headPath);
    await expect(AuditLog.verify(logPath, KEY)).rejects.toThrow(/no head/);
  });

  it("tolerates the one-record skew a crash between append and head-write leaves", async () => {
    await writeRecords(2);
    await copyFile(headPath, `${headPath}.saved`); // head as of 2 records
    await writeRecords(1); // third record; head now says 3
    await copyFile(`${headPath}.saved`, headPath); // crash state: log 3, head 2
    const records = await AuditLog.verify(logPath, KEY);
    expect(records.length).toBe(3);
  });

  it("repairs the crash skew on the next append", async () => {
    await writeRecords(2);
    await copyFile(headPath, `${headPath}.saved`);
    await writeRecords(1);
    await copyFile(`${headPath}.saved`, headPath); // log 3, head 2
    await writeRecords(1); // append accepts the skew and re-pins
    expect((await AuditLog.verify(logPath, KEY)).length).toBe(4);
  });

  it("does not extend the skew tolerance to two records", async () => {
    await writeRecords(2);
    await copyFile(headPath, `${headPath}.saved`);
    await writeRecords(2); // log 4
    await copyFile(`${headPath}.saved`, headPath); // head 2: not a crash state
    await expect(AuditLog.verify(logPath, KEY)).rejects.toThrow(/removed|head/);
  });
});

describe("AuditLog.log (append) refuses to launder tampering", () => {
  it("refuses to extend a log whose head was deleted", async () => {
    await writeRecords(2);
    await rm(headPath);
    const log = new AuditLog(logPath, KEY);
    await expect(log.log("later")).rejects.toThrow(/refusing to extend/);
    // And it wrote nothing: no fresh head appeared to bless the file.
    await expect(readFile(headPath, "utf8")).rejects.toThrow();
  });

  it("refuses to extend a truncated log even though the chain still verifies internally", async () => {
    await writeRecords(3);
    await truncateLastLine();
    const log = new AuditLog(logPath, KEY);
    await expect(log.log("later")).rejects.toThrow(/does not match its signed head/);
  });
});
