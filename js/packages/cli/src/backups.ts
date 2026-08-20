/**
 * Rolling index backups, parity with Python's BackupManager.
 *
 * Every vault mutation leaves a timestamped copy of the encrypted index in
 * `<profile>/backups/`, and — when the profile is configured for it — mirrors
 * that copy to a second location. The filenames match Python's exactly, so
 * the two implementations share one backup directory and either can restore
 * from the other's snapshots.
 *
 * These are copies of the already-encrypted file. Nothing here decrypts
 * anything, and the seed is never needed to make a backup.
 */

import { copyFile, mkdir, chmod, readdir, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { homedir } from "node:os";

/** Matches Python's BackupManager.BACKUP_FILENAME_TEMPLATE. */
export const BACKUP_DIR_NAME = "backups";
const BACKUP_PREFIX = "entries_db_backup_";
const BACKUP_SUFFIX = ".json.enc";

export function backupFilename(timestamp: number): string {
  return `${BACKUP_PREFIX}${timestamp}${BACKUP_SUFFIX}`;
}

/** Expand a leading ~ the way Python's Path.expanduser does. */
function expandHome(p: string): string {
  return p.startsWith("~") ? join(homedir(), p.slice(1)) : p;
}

/**
 * The unix time of the most recent snapshot in `backupDir`, or 0 if there is
 * none.
 *
 * Python throttles with an in-memory `_last_backup_time`, which only works
 * for as long as one BackupManager lives. The TUI is long-lived, but every
 * CLI command is its own process, so an in-memory counter there would mean
 * `backup_interval` is silently ignored for CLI use — the same class of
 * inert setting this code exists to remove. Reading the interval from what is
 * actually on disk gives one answer for both, and matches what a user means
 * by "at most every N seconds".
 */
async function lastBackupTime(backupDir: string): Promise<number> {
  if (!existsSync(backupDir)) return 0;
  let newest = 0;
  for (const name of await readdir(backupDir)) {
    if (!name.startsWith(BACKUP_PREFIX) || !name.endsWith(BACKUP_SUFFIX)) continue;
    const stamp = Number(name.slice(BACKUP_PREFIX.length, -BACKUP_SUFFIX.length));
    if (Number.isFinite(stamp) && stamp > newest) newest = stamp;
  }
  return newest;
}

export interface BackupResult {
  /** Path of the snapshot written, or null when throttled or skipped. */
  written: string | null;
  /** Path of the mirrored copy, when `additional_backup_path` is set. */
  mirrored?: string;
  /** Why no snapshot was written, for callers that surface it. */
  skipped?: "no-index" | "throttled";
  /**
   * The mirror failed. A backup is best-effort: a full or unwritable second
   * location must never turn a successful vault write into a failed command,
   * but it must not be silent either, or the setting is false assurance
   * again — which is the whole point of this module.
   */
  mirrorError?: string;
}

/**
 * Snapshot the encrypted index after a successful write.
 *
 * Called after the vault is saved, matching Python, where `create_backup()`
 * runs after `_save_index()` — so a snapshot is the post-mutation state and
 * the directory reads as a history rather than an undo stack.
 */
export async function createIndexBackup(options: {
  /** Path of the encrypted index that was just written. */
  indexPath: string;
  /** Profile config; reads `backup_interval` and `additional_backup_path`. */
  config: Record<string, unknown>;
  /** Injectable for tests; defaults to now. */
  now?: number;
}): Promise<BackupResult> {
  const { indexPath, config } = options;
  if (!existsSync(indexPath)) return { written: null, skipped: "no-index" };

  const profileDir = dirname(indexPath);
  const backupDir = join(profileDir, BACKUP_DIR_NAME);
  const now = options.now ?? Math.floor(Date.now() / 1000);

  const interval = Number(config["backup_interval"] ?? 0);
  if (Number.isFinite(interval) && interval > 0) {
    const last = await lastBackupTime(backupDir);
    if (last > 0 && now - last < interval) return { written: null, skipped: "throttled" };
  }

  await mkdir(backupDir, { recursive: true });
  const name = backupFilename(now);
  const dest = join(backupDir, name);
  await copyFile(indexPath, dest);
  // copyFile preserves neither mode nor the absence of one reliably across
  // platforms, and the source may predate the 0600 convention. Set it
  // explicitly: this file is the whole vault.
  await chmod(dest, 0o600);

  const result: BackupResult = { written: dest };

  const extra = String(config["additional_backup_path"] ?? "").trim();
  if (!extra) return result;

  try {
    const destDir = expandHome(extra);
    await mkdir(destDir, { recursive: true });
    // Python prefixes with the profile directory's name (the fingerprint) so
    // several profiles can share one additional location without colliding.
    const mirrored = join(destDir, `${basename(profileDir)}_${name}`);
    await copyFile(dest, mirrored);
    await chmod(mirrored, 0o600);
    result.mirrored = mirrored;
  } catch (e) {
    result.mirrorError = (e as Error).message;
  }
  return result;
}

/** Snapshots in a profile's backup directory, newest first. */
export async function listIndexBackups(profileDir: string): Promise<string[]> {
  const backupDir = join(profileDir, BACKUP_DIR_NAME);
  if (!existsSync(backupDir)) return [];
  const names = (await readdir(backupDir)).filter(
    (n) => n.startsWith(BACKUP_PREFIX) && n.endsWith(BACKUP_SUFFIX),
  );
  const withTimes = await Promise.all(
    names.map(async (n) => ({
      path: join(backupDir, n),
      mtime: (await stat(join(backupDir, n))).mtimeMs,
    })),
  );
  return withTimes.sort((a, b) => b.mtime - a.mtime).map((r) => r.path);
}
