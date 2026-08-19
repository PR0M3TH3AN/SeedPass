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
  passwordPolicyFromRecord,
  deriveTotpSecret,
  totpCodeAt,
  hexToBech32,
  bytesToHex,
  deriveSshKeyPair,
  derivePgpKey,
  type Entry,
  type PasswordPolicy,
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
  options: { timestamp?: number; basePolicy?: PasswordPolicy } = {},
): MaterializedSecret {
  switch (entry.kind) {
    case "password": {
      // Policy resolves in three layers, and all three must be present or the
      // derived password is simply wrong. Python builds its PasswordGenerator
      // with the profile config's policy as the base
      // (manager.py: policy=self.config_manager.get_password_policy()) and
      // merges the entry's own `policy` block over it per derivation
      // (_generate_password_for_entry). `basePolicy` is that config base;
      // omitting it silently falls back to the built-in defaults, which is
      // what made any profile with a non-default config policy derive
      // different passwords here than in Python.
      const bip85 = Bip85.fromMnemonic(mnemonic);
      const value = generatePassword(bip85, {
        length: entry.length,
        index: Number(id),
        genVersion: entry.gen_version ?? 1,
        policy: {
          ...(options.basePolicy ?? {}),
          ...passwordPolicyFromRecord((entry as { policy?: unknown }).policy),
        },
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
    case "pgp": {
      const key = derivePgpKey(mnemonic, entry.index, {
        userId: entry.user_id,
        keyType: entry.key_type,
      });
      return {
        value: key.privateKeyArmored,
        descriptor: `PGP private key for ${entry.label}`,
      };
    }
    default: {
      const kind: string = (entry as { kind: string }).kind;
      throw new Error(`unsupported entry kind: ${kind}`);
    }
  }
}
