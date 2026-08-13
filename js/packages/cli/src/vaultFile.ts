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
  const plaintext = await decryptPayload(key, ciphertext);
  const index = parseVaultIndex(JSON.parse(new TextDecoder().decode(plaintext)));
  return { index, mnemonic, path };
}

export async function saveVault(vault: OpenedVault): Promise<void> {
  const key = deriveIndexKeyBytes(vault.mnemonic);
  const payload = await encryptV3(key, utf8(JSON.stringify(vault.index)));
  await writeFile(vault.path, payload, { mode: 0o600 });
}
