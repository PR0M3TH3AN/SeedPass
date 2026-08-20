/**
 * Tamper-evident audit log, chain-compatible with Python's AuditLogger:
 * each record's sig = HMAC-SHA256(key, prev_sig + canonical_payload) where
 * canonical_payload is the compact sort_keys JSON of {timestamp, event,
 * details} and the genesis prev_sig is 64 zeros. The signing key is the
 * profile's index-derivation key (KEY_INDEX), so only the seed holder can
 * extend or verify the chain.
 */

import { appendFile, readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { canonicalJson, hmacSha256Hex, utf8 } from "@seedpass/core";
import { atomicWrite } from "./vaultFile.js";

const GENESIS = "0".repeat(64);

export interface AuditRecord {
  timestamp: string;
  event: string;
  details: Record<string, unknown>;
  sig: string;
}

function isoNow(): string {
  return new Date().toISOString().replace("Z", "+00:00");
}

function signPayload(key: Uint8Array, prevSig: string, payload: string): string {
  return hmacSha256Hex(key, utf8(prevSig + payload));
}

/**
 * A signed head: the record count and last signature, stored beside the log.
 *
 * Chain linkage alone only detects edits *within* the file. Deleting the log
 * (or a suffix of it) leaves a shorter file that still verifies perfectly —
 * an attacker can excise the evidence of their own access. The head pins the
 * expected length, and is itself HMAC'd so it cannot simply be rewritten
 * without the key.
 *
 * The head is created with the log's first record and must accompany it for
 * life: a non-empty log whose head is missing fails BOTH verification and
 * further appends. Appends must refuse too, or truncate-log-plus-delete-head
 * is laundered by whatever ordinary operation appends next, which quietly
 * recreates a head that blesses the shortened file.
 *
 * Honest limit: the head lives beside the log with the same permissions, so
 * an attacker who deletes *both* files leaves a clean slate this cannot
 * detect. Same-uid storage cannot pin "a log once existed"; what the head
 * guarantees is that a log which exists has not been shortened.
 */
interface AuditHead {
  count: number;
  last_sig: string;
  mac: string;
}

export class AuditLog {
  private lastSig = GENESIS;
  private count = 0;
  private loaded = false;

  constructor(
    private readonly path: string,
    private readonly key: Uint8Array,
  ) {}

  private get headPath(): string {
    return `${this.path}.head`;
  }

  private headMac(count: number, lastSig: string): string {
    return hmacSha256Hex(this.key, utf8(`seedpass-audit-head|${count}|${lastSig}`));
  }

  /** Read the head file, verifying its MAC. Null when absent. */
  private static async readHead(headPath: string, key: Uint8Array): Promise<AuditHead | null> {
    if (!existsSync(headPath)) return null;
    let head: AuditHead;
    try {
      head = JSON.parse(await readFile(headPath, "utf8")) as AuditHead;
    } catch {
      throw new Error("audit head is unreadable; the log cannot be trusted");
    }
    const expected = hmacSha256Hex(
      key,
      utf8(`seedpass-audit-head|${head.count}|${head.last_sig}`),
    );
    if (expected !== head.mac) {
      throw new Error("audit head signature mismatch; the log cannot be trusted");
    }
    return head;
  }

  private async loadTail(): Promise<void> {
    if (this.loaded) return;
    if (!existsSync(this.path)) {
      this.loaded = true;
      return;
    }
    // Note the ordering: `loaded` is latched only after the read succeeds.
    // Latching first meant a single transient EACCES left lastSig at GENESIS
    // and the next append re-signed from genesis mid-file, breaking the
    // chain permanently.
    const lines = (await readFile(this.path, "utf8")).split("\n").filter((l) => l.trim());
    if (lines.length > 0) {
      let lastSig: string | undefined;
      try {
        lastSig = (JSON.parse(lines[lines.length - 1]!) as AuditRecord).sig;
      } catch {
        // fall through: an unparseable tail fails the head check below
      }
      // Refuse to extend a log whose head is gone or disagrees: appending
      // would write a fresh head that blesses whatever state the file is in,
      // laundering a truncation. The one tolerated skew is a crash between
      // append and head write, which leaves the log exactly one validly
      // chained record ahead — a state nobody without the HMAC key can forge.
      const head = await AuditLog.readHead(this.headPath, this.key);
      if (!head) {
        throw new Error(
          `audit log at ${this.path} has ${lines.length} records but no head file; ` +
            `refusing to extend it. Either the head was deleted, or the log was ` +
            `written by a build that predates audit heads — verify its provenance, ` +
            `then remove the log to start a fresh chain.`,
        );
      }
      const crashSkew =
        lines.length === head.count + 1 &&
        AuditLog.sigOfLine(lines[head.count - 1]) === head.last_sig;
      const exact = lines.length === head.count && lastSig !== undefined && lastSig === head.last_sig;
      if (!exact && !crashSkew) {
        throw new Error(
          `audit log at ${this.path} does not match its signed head ` +
            `(${lines.length} records vs ${head.count} recorded); refusing to extend it`,
        );
      }
      if (lastSig === undefined) {
        throw new Error(`audit log at ${this.path} has an unparseable tail record`);
      }
      this.lastSig = lastSig;
    }
    this.count = lines.length;
    this.loaded = true;
  }

  private static sigOfLine(line: string | undefined): string | null {
    if (!line) return null;
    try {
      return (JSON.parse(line) as AuditRecord).sig ?? null;
    } catch {
      return null;
    }
  }

  async log(event: string, details: Record<string, unknown> = {}): Promise<void> {
    await this.loadTail();
    const entry = { timestamp: isoNow(), event, details };
    const payload = canonicalJson(entry);
    const sig = signPayload(this.key, this.lastSig, payload);
    await appendFile(this.path, canonicalJson({ ...entry, sig }) + "\n", { mode: 0o600 });
    this.lastSig = sig;
    this.count += 1;
    const head: AuditHead = {
      count: this.count,
      last_sig: sig,
      mac: this.headMac(this.count, sig),
    };
    await atomicWrite(this.headPath, utf8(JSON.stringify(head)));
  }

  /**
   * Verify the whole chain against the signed head.
   *
   * Returns the records, or throws at the first break — including a length
   * or head mismatch, which is what catches deletion rather than editing.
   */
  static async verify(path: string, key: Uint8Array): Promise<AuditRecord[]> {
    const head = await AuditLog.readHead(`${path}.head`, key);
    if (!existsSync(path)) {
      if (head && head.count > 0) {
        throw new Error(
          `audit log is missing but its head records ${head.count} entries; ` +
            `the log was deleted`,
        );
      }
      return [];
    }
    const lines = (await readFile(path, "utf8")).split("\n").filter((l) => l.trim());
    const records: AuditRecord[] = [];
    let prevSig = GENESIS;
    for (let i = 0; i < lines.length; i++) {
      let record: AuditRecord;
      try {
        record = JSON.parse(lines[i]!) as AuditRecord;
      } catch {
        throw new Error(`audit chain broken at line ${i + 1}: unparseable record`);
      }
      const payload = canonicalJson({
        timestamp: record.timestamp,
        event: record.event,
        details: record.details,
      });
      const expected = signPayload(key, prevSig, payload);
      if (expected !== record.sig) {
        throw new Error(`audit chain broken at line ${i + 1}: signature mismatch`);
      }
      prevSig = record.sig;
      records.push(record);
    }
    if (!head) {
      if (records.length > 0) {
        // The length check is the whole defense against truncation, and the
        // head carrying it sits beside the log with the same permissions —
        // so "no head" must fail, or deleting one extra file disables it.
        throw new Error(
          `audit log has ${records.length} records but no head file pinning its ` +
            `length; a truncation would be undetectable. Either the head was ` +
            `deleted, or the log predates audit heads — verify its provenance, ` +
            `then remove the log to start a fresh chain.`,
        );
      }
      return records;
    }
    // Tolerate exactly one validly chained record past the head: a crash
    // between append and head write leaves this state, and nothing without
    // the HMAC key can manufacture it. The next append repairs the head.
    const crashSkew =
      records.length === head.count + 1 &&
      records[head.count - 1]?.sig === head.last_sig;
    if (!crashSkew) {
      if (records.length !== head.count) {
        throw new Error(
          `audit log has ${records.length} records but its head records ` +
            `${head.count}; ${head.count - records.length} were removed`,
        );
      }
      if (prevSig !== head.last_sig) {
        throw new Error("audit log tail does not match its signed head");
      }
    }
    return records;
  }
}
