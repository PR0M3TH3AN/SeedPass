/**
 * Vault file access for the CLI: an encrypted index file (V3 payload, with
 * or without the JSON kdf/ct wrapper) unlocked by the parent seed mnemonic.
 */

import { readFile, open, rename, rm, stat } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { randomBytes } from "node:crypto";
import process from "node:process";
import {
  decryptPayload,
  parseEncryptedFile,
  deriveIndexKeyBytes,
  encryptV3,
  parseVaultIndex,
  utf8,
  type VaultIndex,
} from "@seedpass/core";

export interface OpenedVault {
  index: VaultIndex;
  mnemonic: string;
  path: string;
}

export async function openVault(path: string, mnemonic: string): Promise<OpenedVault> {
  const blob = new Uint8Array(await readFile(path));
  const { ciphertext } = parseEncryptedFile(blob);
  const key = deriveIndexKeyBytes(mnemonic);
  let plaintext: Uint8Array;
  try {
    plaintext = await decryptPayload(key, ciphertext);
  } catch (cause) {
    // Raw decrypt errors ("invalid token encoding") tell the user nothing
    // about which of the two likely causes they are looking at.
    throw new Error(
      `could not decrypt vault at ${path}: the file is corrupt, is not a ` +
        `SeedPass vault, or belongs to a different seed ` +
        `(restore with 'nostr restore' or 'vault import')`,
      { cause },
    );
  }
  const index = parseVaultIndex(JSON.parse(new TextDecoder().decode(plaintext)));
  return { index, mnemonic, path };
}

/**
 * Persist the vault.
 *
 * Writes must survive a crash and must not let two concurrent commands
 * silently discard each other's changes, so this:
 *   1. validates the index before anything touches disk,
 *   2. takes an exclusive lock for the read-modify-write window,
 *   3. writes a temp file in the same directory, fsyncs it, and renames
 *      over the target (atomic within a filesystem),
 *   4. fsyncs the directory so the rename itself is durable.
 */
export async function saveVault(vault: OpenedVault): Promise<void> {
  await withVaultLock(vault.path, () => saveVaultHoldingLock(vault));
}

/**
 * Save without taking the lock — for callers already inside `withVaultLock`.
 *
 * Serializing only the write is not enough: two commands that each read,
 * mutate and write will still lose one set of changes. The lock has to span
 * the whole read-modify-write cycle, which is what `mutateVault` does.
 */
export async function saveVaultHoldingLock(vault: OpenedVault): Promise<void> {
  // A malformed index must never reach disk: a bad write here is what makes
  // a vault unopenable afterwards.
  parseVaultIndex(JSON.parse(JSON.stringify(vault.index)), { migrate: false });

  const key = deriveIndexKeyBytes(vault.mnemonic);
  const payload = await encryptV3(key, utf8(JSON.stringify(vault.index)));
  await atomicWrite(vault.path, payload);
}

/** Write `data` to `path` atomically, with 0600 and durability. */
export async function atomicWrite(path: string, data: Uint8Array): Promise<void> {
  const dir = dirname(path);
  const tmp = join(dir, `.${basename(path)}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`);
  const handle = await open(tmp, "wx", 0o600);
  let renamed = false;
  try {
    // A short write is not an error in POSIX, and ignoring it is how a
    // truncated file gets fsynced and renamed over the only good copy —
    // silently, with a success exit code. Loop until everything lands and
    // fail loudly if it cannot.
    let written = 0;
    while (written < data.length) {
      const { bytesWritten } = await handle.write(data, written, data.length - written);
      if (bytesWritten <= 0) {
        throw new Error(
          `short write to ${tmp}: wrote ${written} of ${data.length} bytes`,
        );
      }
      written += bytesWritten;
    }
    if (written !== data.length) {
      throw new Error(`short write to ${tmp}: wrote ${written} of ${data.length} bytes`);
    }
    // fchmod on the handle, not the path: a path-based chmod after the file
    // is visible can be redirected through a symlink.
    await handle.chmod(0o600);
    await handle.sync();
    await handle.close();
    await rename(tmp, path);
    renamed = true;
  } finally {
    if (!renamed) {
      // Never leave a partial ciphertext copy behind.
      await handle.close().catch(() => {});
      await rm(tmp, { force: true }).catch(() => {});
    }
  }
  const dirHandle = await open(dir, "r");
  try {
    await dirHandle.sync();
  } catch {
    // Directory fsync is not supported everywhere; the rename still lands.
  } finally {
    await dirHandle.close();
  }
}

/**
 * Hold an exclusive lock for the duration of `fn`.
 *
 * `wx` on a sidecar file is the portable primitive here: creation is atomic,
 * so exactly one holder wins. A stale lock (crashed holder) is broken after
 * LOCK_STALE_MS rather than wedging the CLI forever.
 */
const LOCK_STALE_MS = 30_000;

/** Is a pid still running (and therefore still holding its lock)? */
function pidAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    // EPERM means it exists but belongs to someone else — still alive.
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
}

export async function withVaultLock<T>(path: string, fn: () => Promise<T>): Promise<T> {
  const lockPath = `${path}.lock`;
  // A token unique to this acquisition. Releasing or breaking a lock without
  // checking it is how two processes end up both believing they hold it:
  // rm-then-create is not atomic, so a slow holder's lock can be deleted by
  // a racer that already decided it was stale.
  const token = `${process.pid}:${randomBytes(12).toString("hex")}`;
  const deadline = Date.now() + LOCK_STALE_MS;

  for (;;) {
    try {
      const handle = await open(lockPath, "wx", 0o600);
      try {
        await handle.write(token);
        await handle.sync();
      } finally {
        await handle.close();
      }
      break;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;

      let holder = "";
      let age = 0;
      try {
        holder = await readFile(lockPath, "utf8");
        age = Date.now() - (await stat(lockPath)).mtimeMs;
      } catch {
        continue; // released between our attempts
      }
      const holderPid = Number.parseInt(holder.split(":")[0] ?? "", 10);

      // Only break a lock whose owner is demonstrably gone. Age alone is a
      // guess — a slow disk or a suspended laptop is not a crash.
      if (!pidAlive(holderPid) && age > LOCK_STALE_MS) {
        // Steal atomically: move the stale file aside and only proceed if
        // this process is the one that managed to move it.
        const claim = `${lockPath}.claim.${randomBytes(8).toString("hex")}`;
        try {
          await rename(lockPath, claim);
          await rm(claim, { force: true });
        } catch {
          // Another process won the steal; fall through and retry.
        }
        continue;
      }
      if (Date.now() > deadline) {
        throw new Error(
          `another SeedPass process (pid ${holderPid || "unknown"}) is holding ` +
            `${lockPath}; retry, or remove it if no such process is running`,
        );
      }
      await new Promise((r) => setTimeout(r, 25));
    }
  }

  try {
    return await fn();
  } finally {
    // Release only if we still own it: a lock broken out from under us
    // belongs to someone else now, and deleting it would evict them.
    try {
      const current = await readFile(lockPath, "utf8");
      if (current === token) await rm(lockPath, { force: true });
    } catch {
      // Already gone.
    }
  }
}
