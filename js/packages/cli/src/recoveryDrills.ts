/**
 * Recovery drills — parity with the drill half of
 * src/seedpass/core/agent_recovery.py.
 *
 * A drill records that someone checked a backup is present and current. The
 * log is HMAC-chained the way the audit log is: each record signs
 * `previous_signature || canonical_record`, so removing or reordering an
 * entry breaks every signature after it. That matters because the value of a
 * drill log is entirely in it being an honest history — one you can silently
 * edit records nothing.
 *
 * The drill key is generated once and kept at 0600. It authenticates the
 * chain against tampering by anyone who cannot read it; it is not a secret
 * about the vault, and losing it invalidates the history rather than
 * exposing anything.
 */

import { randomBytes } from "node:crypto";
import { appendFile, readFile, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { hmacSha256Hex, utf8 } from "@seedpass/core";
import { atomicWrite } from "./vaultFile.js";

export const DRILL_KEY_FILENAME = "agent_recovery_drill.key";
export const DRILL_LOG_FILENAME = "agent_recovery_drills.log";
/** Genesis link, matching Python's 64 zeroes. */
const GENESIS_SIG = "0".repeat(64);

export interface DrillRecord {
  timestamp_utc: string;
  fingerprint: string;
  backup_path: string;
  backup_exists: boolean;
  backup_size: number;
  backup_age_days: number | null;
  expected_max_age_days: number | null;
  stale: boolean;
  simulated: boolean;
  status: string;
  sig?: string;
}

export function drillKeyPath(appRoot: string): string {
  return join(appRoot, DRILL_KEY_FILENAME);
}

export function drillLogPath(appRoot: string): string {
  return join(appRoot, DRILL_LOG_FILENAME);
}

async function loadDrillKey(appRoot: string): Promise<Uint8Array> {
  const path = drillKeyPath(appRoot);
  if (existsSync(path)) return new Uint8Array(await readFile(path));
  const key = randomBytes(32);
  await atomicWrite(path, new Uint8Array(key));
  return new Uint8Array(key);
}

/**
 * Canonical JSON with sorted keys and no whitespace.
 *
 * The signature covers this exact string, so it must match Python's
 * `json.dumps(..., sort_keys=True, separators=(",", ":"))` byte for byte or
 * neither implementation can verify the other's chain.
 */
function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const keys = Object.keys(value as Record<string, unknown>).sort();
  return `{${keys
    .map((k) => `${JSON.stringify(k)}:${canonical((value as Record<string, unknown>)[k])}`)
    .join(",")}}`;
}

function sign(key: Uint8Array, previousSig: string, record: DrillRecord): string {
  return hmacSha256Hex(key, utf8(`${previousSig}${canonical(record)}`));
}

async function readLines(path: string): Promise<string[]> {
  if (!existsSync(path)) return [];
  const text = await readFile(path, "utf8");
  return text.split("\n").filter((line) => line.trim().length > 0);
}

async function latestSig(path: string): Promise<string> {
  const lines = await readLines(path);
  if (lines.length === 0) return GENESIS_SIG;
  try {
    const payload = JSON.parse(lines[lines.length - 1]!) as { sig?: string };
    return String(payload.sig ?? GENESIS_SIG);
  } catch {
    return GENESIS_SIG;
  }
}

/** Record a drill against `backupPath`. */
export async function recordRecoveryDrill(
  appRoot: string,
  options: {
    fingerprint: string;
    backupPath: string;
    simulated: boolean;
    expectedMaxAgeDays?: number | null;
    now?: number;
  },
): Promise<DrillRecord> {
  const now = options.now ?? Date.now();
  let exists = false;
  let size = 0;
  let modifiedMs = 0;
  try {
    const info = await stat(options.backupPath);
    exists = true;
    size = info.size;
    modifiedMs = info.mtimeMs;
  } catch {
    // A missing backup is the finding, not an error: that is what a drill is
    // for. It reports status "warning" below.
  }
  const ageDays = exists ? Math.floor((now - modifiedMs) / 86_400_000) : null;
  const expectedMaxAgeDays = options.expectedMaxAgeDays ?? null;
  const stale =
    ageDays !== null && expectedMaxAgeDays !== null && ageDays > expectedMaxAgeDays;

  const record: DrillRecord = {
    timestamp_utc: new Date(now).toISOString(),
    fingerprint: String(options.fingerprint),
    backup_path: options.backupPath,
    backup_exists: exists,
    backup_size: size,
    backup_age_days: ageDays,
    expected_max_age_days: expectedMaxAgeDays,
    stale,
    simulated: Boolean(options.simulated),
    status: exists && !stale ? "ok" : "warning",
  };

  const path = drillLogPath(appRoot);
  const key = await loadDrillKey(appRoot);
  const sig = sign(key, await latestSig(path), record);
  const full: DrillRecord = { ...record, sig };
  // Append rather than rewrite: a chained log that gets rewritten wholesale
  // is one lost write away from losing its history.
  await appendFile(path, `${JSON.stringify(full, Object.keys(full).sort())}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  return full;
}

export async function listRecoveryDrills(
  appRoot: string,
  options: { limit?: number } = {},
): Promise<DrillRecord[]> {
  const limit = options.limit ?? 20;
  const lines = await readLines(drillLogPath(appRoot));
  const out: DrillRecord[] = [];
  for (const line of lines.slice(-limit)) {
    try {
      const payload = JSON.parse(line);
      if (typeof payload === "object" && payload !== null) out.push(payload as DrillRecord);
    } catch {
      // Skip unparseable lines here; verify() is what reports them.
    }
  }
  return out;
}

export interface DrillVerification {
  valid: boolean;
  checked: number;
  errors: string[];
}

/** Verify the chain, naming every line that fails and why. */
export async function verifyRecoveryDrills(
  appRoot: string,
  options: { limit?: number } = {},
): Promise<DrillVerification> {
  const path = drillLogPath(appRoot);
  if (!existsSync(path)) return { valid: true, checked: 0, errors: [] };
  let lines = await readLines(path);
  if (lines.length === 0) return { valid: true, checked: 0, errors: [] };
  const limit = options.limit ?? 200;
  if (limit > 0) lines = lines.slice(-limit);

  const key = await loadDrillKey(appRoot);
  let previousSig = GENESIS_SIG;
  const errors: string[] = [];
  let checked = 0;

  for (const [index, line] of lines.entries()) {
    let record: unknown;
    try {
      record = JSON.parse(line);
    } catch {
      errors.push(`invalid_json_line:${index}`);
      continue;
    }
    if (typeof record !== "object" || record === null) {
      errors.push(`invalid_record_line:${index}`);
      continue;
    }
    const body = { ...(record as Record<string, unknown>) };
    const sig = String(body["sig"] ?? "");
    if (!sig) {
      errors.push(`missing_sig_line:${index}`);
      continue;
    }
    delete body["sig"];
    if (sign(key, previousSig, body as unknown as DrillRecord) !== sig) {
      errors.push(`sig_mismatch_line:${index}`);
    }
    // Chain forward on the RECORDED signature, not the computed one: a single
    // tampered record must break every link after it, not just its own.
    previousSig = sig;
    checked++;
  }
  return { valid: errors.length === 0, checked, errors };
}
