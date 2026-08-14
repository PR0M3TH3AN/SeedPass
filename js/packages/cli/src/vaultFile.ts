/**
 * Vault file access for the CLI: an encrypted index file (V3 payload, with
 * or without the JSON kdf/ct wrapper) unlocked by the parent seed mnemonic.
 */

import { readFile, writeFile } from "node:fs/promises";
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

export async function saveVault(vault: OpenedVault): Promise<void> {
  const key = deriveIndexKeyBytes(vault.mnemonic);
  const payload = await encryptV3(key, utf8(JSON.stringify(vault.index)));
  await writeFile(vault.path, payload, { mode: 0o600 });
}
