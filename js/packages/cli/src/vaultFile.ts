/**
 * Vault file access for the CLI: an encrypted index file (V3 payload, with
 * or without the JSON kdf/ct wrapper) unlocked by the parent seed mnemonic.
 */

import { readFile, open, rename, rm, stat, chmod } from "node:fs/promises";
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
  try {
    await handle.write(data);
    await handle.sync();
  } finally {
    await handle.close();
  }
  await rename(tmp, path);
  // Repair permissions if the target already existed with looser modes:
  // writeFile's mode argument applies only on creation.
  await chmod(path, 0o600);
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

export async function withVaultLock<T>(path: string, fn: () => Promise<T>): Promise<T> {
  const lockPath = `${path}.lock`;
  const deadline = Date.now() + LOCK_STALE_MS;
  for (;;) {
    try {
      const handle = await open(lockPath, "wx", 0o600);
      await handle.write(String(process.pid));
      await handle.close();
      break;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
      let age = 0;
      try {
        age = Date.now() - (await stat(lockPath)).mtimeMs;
      } catch {
        continue; // holder released it between our attempts
      }
      if (age > LOCK_STALE_MS) {
        await rm(lockPath, { force: true });
        continue;
      }
      if (Date.now() > deadline) {
        throw new Error(
          `another SeedPass process is holding ${lockPath}; retry, or remove it if no process is running`,
        );
      }
      await new Promise((r) => setTimeout(r, 25));
    }
  }
  try {
    return await fn();
  } finally {
    await rm(lockPath, { force: true });
  }
}
