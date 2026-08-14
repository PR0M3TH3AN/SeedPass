/**
 * Secret materialization: derive or read the plaintext for an entry.
 *
 * This module is the ONLY place the CLI turns an entry into a secret value.
 * Callers decide what happens to it: `reveal` prints it (explicit egress),
 * `use` delivers it to a sink without letting it touch stdout.
 */

import {
  Bip85,
  generatePassword,
  deriveTotpSecret,
  totpCodeAt,
  hexToBech32,
  bytesToHex,
  deriveSshKeyPair,
  type Entry,
  type VaultIndex,
} from "@seedpass/core";

export interface MaterializedSecret {
  /** The secret itself. Handle with care; never log. */
  value: string;
  /** What kind of thing it is, for sink labeling. */
  descriptor: string;
}


export function materializeSecret(
  index: VaultIndex,
  id: string,
  entry: Entry,
  mnemonic: string,
  options: { timestamp?: number } = {},
): MaterializedSecret {
  switch (entry.kind) {
    case "password": {
      // Per-profile policy overrides live in the config file (not the
      // index); the default policy applies until profile management is
      // ported.
      const bip85 = Bip85.fromMnemonic(mnemonic);
      const value = generatePassword(bip85, {
        length: entry.length,
        index: Number(id),
        genVersion: entry.gen_version ?? 1,
      });
      return { value, descriptor: `password for ${entry.label}` };
    }
    case "totp": {
      const secret =
        entry.secret ?? deriveTotpSecret(mnemonic, entry.index ?? 0);
      const ts = options.timestamp ?? Math.floor(Date.now() / 1000);
      const value = totpCodeAt(secret, ts, entry.period, entry.digits);
      return { value, descriptor: `TOTP code for ${entry.label}` };
    }
    case "key_value":
      return { value: entry.value, descriptor: `value of ${entry.label}` };
    case "document":
      return { value: entry.content, descriptor: `document ${entry.label}` };
    case "nostr": {
      // Nostr ENTRY keys use the default BIP-85 app 39 path (see
      // EntryManager.get_nostr_key_pair) — NOT app 1237, which is only for
      // the sync client identity.
      const bip85 = Bip85.fromMnemonic(mnemonic);
      const entropy = bip85.deriveEntropy({ index: entry.index, entropyBytes: 32 });
      return {
        value: hexToBech32(bytesToHex(entropy), "nsec"),
        descriptor: `nsec for ${entry.label}`,
      };
    }
    case "seed":
    case "managed_account": {
      const bip85 = Bip85.fromMnemonic(mnemonic);
      const value = bip85.deriveMnemonic(entry.index, entry.word_count);
      return { value, descriptor: `derived mnemonic for ${entry.label}` };
    }
    case "ssh": {
      const pair = deriveSshKeyPair(mnemonic, entry.index);
      // The private key is the secret; the public key is printed alongside
      // only by `entry ssh-public`, which is not a secret-bearing command.
      return { value: pair.privateKeyPem, descriptor: `SSH private key for ${entry.label}` };
    }
    case "pgp":
      throw new Error(
        "PGP key material is not ported yet (see the compatibility matrix)",
      );
    default: {
      const kind: string = (entry as { kind: string }).kind;
      throw new Error(`unsupported entry kind: ${kind}`);
    }
  }
}
